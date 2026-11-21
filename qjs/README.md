# QuickJS bytecode plugins

Disassembly, analysis, assembly, stack pseudo syntax and serialized-object
loading for a QuickJS VM selected at build time.

```sh
make QJS_REPO=https://github.com/quickjs-ng/quickjs.git QJS_REF=HEAD
make user-install
```

`QJS_REPO` chooses the repository to clone into `.quickjs`; `QJS_REF` selects
its revision. Builds fetch that revision into the generated clone. For an
existing, possibly modified source tree:

```sh
make QJS_DIR=/absolute/path/to/quickjs user-install
```

Requires current radare2, a C compiler, make, git and pkg-config. Override
`QJS_CFLAGS`, `QJS_SOURCES` and `QJS_LIBS` for custom VM build options or
additional runtime dependencies. `R2`, `PKG_CONFIG`, `CC`, `CFLAGS`, `CPPFLAGS`,
`LDFLAGS`, `SOEXT`, `PLUGDIR` and `DESTDIR` are also configurable. `install`
and `uninstall` use the system plugin directory; `user-install` and
`user-uninstall` use the user directory.

The arch and pseudo plugins use the selected `quickjs-opcode.h` directly,
excluding compiler-only temporary instructions. The bin plugin compiles the
selected `quickjs.c` and its support sources, uses `JS_ReadObject`, and walks
its function/module objects. This small adapter includes the runtime source
because QuickJS does not expose function bytecode through its public API.
There is no separate serialized-format implementation or hardcoded version
list. Forks changing the private function/module structures may need an adapter
change. Runtime symbols stay private to the plugin, separate from r2's JS VM.

QuickJS-NG can compile a native serialized object with:

```sh
qjsc -b -o sample.qjbc sample.js
r2 -A sample.qjbc
```

Bellard's `qjsc -c` emits byte arrays in C; extract an array as binary first.
For raw instruction streams, use `r2 -n -a qjs instructions.bin` or
`rasm2 -a qjs 'push_i32 -42; return'`.

```text
is
pdf @ sym.answer
e asm.pseudo=true
pdf @ sym.answer
pa push_i32 -42
pa goto8 0x100
```

The bin plugin maps decoded functions consecutively at `0x10000000` and adds
function symbols. These are runtime buffers, with runtime atom IDs, rather
than physical offsets into the serialized file. Assembly edits those buffers;
it does not rewrite the serialized object. Branch operands are absolute target
addresses. Other operands are numeric indices/IDs. Compact operands remain in
the mnemonic (`get_loc0`, `call2`). `cfg.bigendian` selects the byte order for
raw streams; decoded runtime buffers use the host byte order.

Pseudo output shows explicit stack operations for common instructions and
keeps other VM mnemonics. It does not reconstruct JavaScript source or emulate
the VM. The experimental `R2JSBC`/LZ4 wrapper in radare2 PR #27166 must be
unpacked into native objects first.

Only open bytecode from a trusted producer with the matching VM sources:
QuickJS's object reader is not designed for untrusted input. Loading calls
`JS_ReadObject`, never `JS_EvalFunction`, and does not execute script bodies.

The r2pm package accepts the same Makefile variables:

```sh
QJS_REPO=https://github.com/your/quickjs.git QJS_REF=my-vm r2pm -ci qjs
QJS_DIR=/absolute/path/to/quickjs r2pm -ci qjs
```
