# MD32 architecture plugin

Native radare2 `RArchPlugin` for the MediaTek MD32 **MS15E30** ISA. The decoder
covers all **258 encoding forms** in the public vendor disassembler, including
16/32-bit instructions, packed instruction pairs, DSP operations, control
registers, and hardware-loop setup. It has no runtime dependency on Python,
Ghidra, Capstone, or vendor binutils.

The supplied MT6877 **uSIP** binaries use a different encoding. Select the
explicit, experimental `usip` CPU for these; its support is partial.

## Build and use

Requires radare2 development headers/libraries, `pkg-config`, a C compiler, and
make. Tested with radare2 6.2.5 on macOS arm64.

```sh
make
make install
r2 -a md32 -b 32 -e cfg.bigendian=true firmware.be.bin
```

`make install` copies the architecture and assembly parse plugins to
`r2 -H R2_USER_PLUGINS`. Override `R2_PLUGIN_PATH` to choose another location.
`make uninstall` removes both.
Without installation, load the built library using `L /absolute/path/arch_md32.dylib`
inside r2 (`.so` on Linux), then set `e asm.arch=md32`.

For pseudocode display, enable `e asm.pseudo=true`. The `md32` assembly parser
is selected automatically with `asm.arch=md32`; select it explicitly with
`e asm.parser=md32` if needed. Without installation, load `asm_md32.dylib`
alongside `arch_md32.dylib` before selecting the architecture.

The parser covers scalar moves, arithmetic, bit operations, signed/unsigned
comparisons, calls, jumps and Harvard data-memory accesses. For example,
`lw r2, (r1+=0x8)` becomes `r2 = dmem32[r1]; r1 += 0x8`. Signed byte/halfword
loads use `sext8`/`sext16`; packed pairs display as `parallel { ...; ...; }`.
Delayed control flow and unresolved DSP operations retain their assembly text.
uSIP branches retain numeric condition identifiers, return markers carry an
unresolved-extension annotation, and unknown encodings remain raw directives.
This is a display parser; it does not add instruction encodings or ESIL semantics.

Instructions use big-endian byte order and two-byte alignment. Older VPU/DSP
blobs store the instruction stream in reversed **four-byte storage words**.
Normalize those files before opening them:

```sh
python3 tools/swap_words.py vpu_p.bin firmware.be.bin
```

This is not ordinary per-instruction byte swapping: a four-byte storage word
may contain two instructions or part of an instruction crossing its boundary.
Do not apply this conversion to the already big-endian uSIP samples.

## Supplied uSIP samples

```sh
r2 -a md32 -b 32 -e cfg.bigendian=true -c 'e asm.cpu=usip' \
  -m 0x400e0000 third_party/r2pkg/bin/usip_sec0.bin
r2 -a md32 -b 32 -e cfg.bigendian=true -c 'e asm.cpu=usip' \
  -m 0x1ca34000 third_party/r2pkg/bin/usip_ddr.bin
```

Optional symbol flags, generated directly from the supplied inventory:

```sh
python3 tools/usip_symbols.py --section sec0 > /tmp/usip-sec0.r2
python3 tools/usip_symbols.py --section ddr > /tmp/usip-ddr.r2
```

Load the corresponding script with `. /tmp/usip-sec0.r2` or
`. /tmp/usip-ddr.r2`. The first 0x400 bytes of sec0 are the vector table;
use the symbol inventory to choose code entry points. These are supplied load
aliases; the reset-vector conflict reported by `tools/analyze_firmware.py`
means they are not a validated boot memory map.

uSIP support currently recognizes 16/32-bit return, save, and restore forms,
conditional branches, and two observed call patterns. These are corpus-derived
rules, not a recovered vendor ISA specification. Unknown instructions remain
`.hword`/`.word` with the correct length and `unk` analysis type. The register
ABI and ALU/load/store encodings
are unresolved. Branch conditions use numeric names (`b0` through `b7`); their
comparison meanings are unknown. No MS15E30 register profile or ESIL is applied
to uSIP.

## Analysis and emulation

The MS15E30 decoder provides operation types, direct targets, register-indirect
jumps/calls, returns, condition codes, delay counts, memory widths and signedness,
operand values, JSON operands, and the register profile. Relative targets wrap
at 32 bits. Delay-slot counts are in decoded instructions/bundles; the
fallthrough address is computed from their actual lengths when lookahead is
available. If lookahead is insufficient, delayed fallthrough remains unknown.

ESIL covers register/immediate moves, ordinary integer arithmetic and logic,
logical/arithmetic shifts, leading-bit counts, scalar min/max, conditional
inversion, multiplication, loads/stores, and immediate control flow,
including signed/unsigned comparisons. It does not model carry/borrow flags,
DSP saturation/rounding, interrupt status restoration, delayed control-flow
execution, hardware-loop execution, or parallel bundle execution. These
instructions still disassemble. Hardware-loop setup reports the loop-end
reference; automatic loop back edges are not inferred.

A packed pair is one four-byte decode unit, displayed as `slot0 | slot1`.
Control flow in its second slot is retained. Other pairs have `unk` as their
aggregate operation type, and operand JSON records their slot numbers. This
preserves decode boundaries without inventing a sequential execution model.
Program and data memory are separate on MD32; r2's usual flat memory view needs
appropriate maps for your firmware before memory emulation is useful.

## Verification

```sh
make test
```

This runs native decoder/parser tests, exhaustive halfword/truncation checks, actual r2
plugin/analysis/ESIL tests, and checks all **1,128 functions / 100,275 instruction
lengths** against the supplied uSIP inventory. The original private `dsp.bin` and
`DbgInfo` files are not required.

Optional independent vendor comparison (see [research notes](doc/research.md)
for downloads and checksums):

```sh
python3 -m venv /tmp/md32-verify
/tmp/md32-verify/bin/pip install unicorn
/tmp/md32-verify/bin/python test/test_oracle.py /tmp/md32-objdump
```

The test emulates the vendor's original x86-64 disassembly function using
Unicorn and compares decoded text, operands, validity, and lengths. Use
`--quick` for a smaller run or `--firmware firmware.be.bin` to add a firmware
image. The checked run included **141,924 cases with zero mismatches**, including
all halfword patterns, randomized operands for every vendor instruction form,
packed pairs, and the MT8173 VPU program image.

See [doc/research.md](doc/research.md) for provenance, the binutils findings,
MD380 distinction, and remaining research questions.

## Firmware exploration and strict ESIL execution

The newer `third_party/v2/r2pkg` bundle adds BRP and a CSV inventory covering
1,301 functions. `tools/analyze_firmware.py` reports the startup probes,
purpose/structure, points of interest, missing encodings, string scan, mapping
conflicts and plugin fixes, and writes the complete listings plus the
three-image loader script into a local `usipdata/` directory. Those artifacts
are derived from the third-party firmware, so the directory is gitignored and
not shipped.

```sh
make test
python3 tools/analyze_firmware.py
r2 -a md32 -c '. usipdata/load-usip.r2' malloc://1

tools/md32-run --cpu usip \
  --image third_party/v2/r2pkg/bin/usip_sec0.bin@0x400e0000 --vector
```

The runner uses separate code/data maps. Add `--data FILE@BASE` for known data,
`--ram BASE:SIZE` for uninitialized RAM, `--zero BASE:SIZE` for deliberately
zeroed RAM, and `--reg NAME=VALUE` for known register state. It reports JSON and
stops on unresolved semantics, unknown memory/register state or unmodeled MMIO.
A reported stop is an analysis result, not a successful firmware boot. The
supplied uSIP reset/startup probes currently complete zero instructions.
