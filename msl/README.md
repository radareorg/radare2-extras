# Memory Slice (.msl) plugins for radare2

radare2 can open and emulate **Memory Slice** (`.msl`) process memory dumps
produced by [memslicer](https://github.com/MemorySlice/memslicer). A slice is a
static snapshot of a single process: its virtual address space (with per-page
acquisition state) plus, when captured, the per-thread CPU registers. Because a
slice is static, "execution" is driven by **emulation (ESIL)**.

This directory ships the support as loadable radare2 plugins.

| Plugin | File | Role |
|--------|------|------|
| `io.msl`    | `io_msl.c`    | Exposes the virtual address space (`msl://`), and acts as a debug IO so a slice can be opened in debug mode without spawning a process. Verifies the SHA-256 integrity chain on open. |
| `bin.msl`   | `bin_msl.c`   | Parses the slice as a CORE object: architecture/bits/OS, entrypoint (the captured PC), and one memory map per contiguous run of captured pages. |
| `debug.msl` | `debug_msl.c` | Emulated debug backend: seeds the register file from the captured Thread Context and steps via ESIL, including reverse execution (`dsb`/`aesb`). |
| `core.msl`  | `core_msl.c`  | Producer: adds `dgm`/`dgma` to write a `.msl` from a live debug session. |

**Compression:** lz4-compressed regions are decoded transparently by the
`io.msl` plugin (open the slice as `msl://…`). zstd-compressed regions cannot
be decoded — radare2 has no zstd — and read back as the fill byte with a
warning; recapture with `memslicer … -c lz4` (or `-c none`), or use the
Python `memslicer-emu` tool, which handles both codecs. The `bin.msl` map path
(`r2 dump.msl`) cannot express compressed regions as file maps either, so for
compressed slices use the `msl://` URI. **Encrypted** slices are not supported.
Failed and unmapped pages (and unbacked addresses) read back as the fill byte.

## Build & install

Requires a radare2 development install (`pkg-config --exists r_core`).

```
make
make install        # installs the 4 plugins into R2_USER_PLUGINS
```

`make install` copies the `.so`/`.dylib` into `$(R2PM_PLUGDIR)` (the per-user
plugin directory reported by `r2 -H R2_USER_PLUGINS`). Verify they loaded:

```
$ r2 -qc 'Lo~msl; Lb~msl; Ld~msl; Lc~msl' --
```

## Inspecting a slice (analysis)

Open the file normally — `bin.msl` provides the maps, architecture and
entrypoint:

```
$ r2 dump.msl
[0x00401000]> i~type,arch,bits     # CORE, x86, 64
[0x00401000]> iS                   # memory maps (one per captured run)
[0x00401000]> s entry0; pd 8       # disassemble from the captured PC
[0x00401000]> px @ 0x7ffff000      # read captured memory
```

For a raw virtual-address view without bin metadata, use the `msl://` URI, which
goes straight through `io.msl`:

```
$ r2 msl://dump.msl
[0x00000000]> px @ 0x401000
```

On open, `io.msl` recomputes the per-block SHA-256 chain and the End-of-Capture
`FileHash`; a mismatch (truncated or tampered slice) prints a warning but the
slice is still indexed and readable.

## Emulated debugging (advancing execution)

Open the slice as an emulated debug target. `io.msl` is a debug IO, so this does
**not** spawn a process:

```
$ r2 -D msl -d msl://dump.msl
```

On attach the backend sets the architecture from the slice header, initializes
the ESIL VM, enables `io.cache` (so emulated writes don't touch the dump) and
**seeds every register from the Current thread's Thread Context**, then seeks to
the captured program counter.

Single-step and inspect with the usual debugger commands:

```
[0x00401000]> dr rip rax rbx        # registers as captured
[0x00401000]> ds                    # step one instruction
[0x00401000]> dr rax                # observe the change
[0x00401000]> dso                   # step over
[0x00401000]> dsb                   # step BACK (reverse / time-travel)
[0x00401000]> db 0x401040 ; dc      # run to a breakpoint
[0x00401000]> dr rcx=0x10           # modify a register
[0x00401000]> pd 4 @ rip            # disassemble at the current PC
```

**Reverse execution.** The backend records ESIL step history
(`esil.maxbacksteps`, default 256), so `dsb` (or `aesb`) steps execution
*backwards*, reverting both the program counter and register/memory changes —
useful for walking back from a fault or an interesting state in the snapshot.

The backend clears `cfg.debug` after seeding so that `ds`/`dso` dispatch to the
ESIL stepper instead of radare2's `r_debug_step` machinery (software
breakpoints, arena swap, trace), which assumes a live ptrace process. The raw
ESIL commands (`aes`, `aesu 0x401020`, `aer rax=...`) work as well.

`dc` runs to a breakpoint via ESIL. A slice has no program exit and unmapped
fetches read as the fill byte (which decodes as instructions), so `dc` *without*
a breakpoint is bounded by `esil.maxsteps` (defaulted to 1,000,000 by this
backend) rather than running forever — set `e esil.maxsteps=0` for unlimited.
The seek follows the PC after each step (`dbg.follow=1`), so the disassembly and
visual modes track execution.

> Note: routing `dc` to ESIL when `cfg.debug` is unset is a small radare2 core
> change (it benefits any emulated backend, not just msl). It is proposed
> separately upstream; without it, use `aec` instead of `dc` on older r2.

## Producing a slice from radare2

The `core.msl` plugin adds `dgm` (debug-generate memory-slice). While debugging
a process, write the current state as a slice:

```
[0xphysical]> dgm dump.msl        # or just `dgm` -> <pid>.msl
[0xphysical]> dgma dump.msl       # include all maps (no large-map skip)
```

It writes the file header, a Process Identity block, a Thread Context with the
current thread's registers, and one Memory Region per debug map (three-state
page map: pages that read back become Captured, the rest Failed). The integrity
chain uses SHA-256 (radare2 has no BLAKE3; the format allows SHA-256 via
HashAlgo 0x01). The resulting `.msl` is readable by these plugins and by
memslicer / `memslicer-emu`.

Maps are read in 1 MiB chunks; unreadable maps are skipped. By default `dgm`
skips very large maps (over 512 MiB — e.g. the macOS dyld shared cache) so the
dump stays small and fast; use `dgma` to include everything.

## Testing

`test/genmsl.py` writes a small but fully-formed `.msl` (file header, Process
Identity, Thread Context, one Memory Region, End-of-Capture) with a valid
SHA-256 chain — handy for exercising the read path without a live target:

```
$ python3 test/genmsl.py /tmp/sample.msl
$ r2 -qc 'iS' /tmp/sample.msl                   # bin: region.0 @ 0x1000
$ r2 -qc 's 0x1000; p8 8' msl:///tmp/sample.msl # io: captured bytes
$ r2 -D msl -d msl:///tmp/sample.msl            # emulated debug; dr, ds, dsb
```

## Format reference

The `.msl` binary format is specified in the
[Memory Slice specification](https://github.com/MemorySlice). The plugins read:
the 64/128-byte file header (`MEMSLICE` magic, OS/arch/PID), Memory Region
blocks (`0x0001`, with the two-bit page-state map), and Thread Context blocks
(`0x0011`, per-thread register file).
