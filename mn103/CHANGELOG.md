# Changelog

## Unreleased

### Initial release

* `tools/gen_mn103_tables.py` / `isa/m10300-opc.c` / `mn103_opcodes.h`: the
  GNU binutils MN10300 opcode table (1129 rows, 89 operand descriptors) as C
  arrays, with the `udf` placeholder rows moved after the named rows of the
  same encoding.
* `mn103_decode.c`: the length rule, first-match lookup and operand extraction
  of `opcodes/m10300-dis.c` ported to C; machine levels `mn10300`, `am30`,
  `am33`, `am33-2` as a superset chain; binutils syntax with hexadecimal
  numbers.
* `arch_mn103.c`: the `mn103` architecture plugin: analysis types for every
  row, control flow (branches with conditions, loops through `lar`, direct and
  register jumps and calls, returns, traps), loads/stores with size, base,
  index, displacement and absolute address, stack deltas for `add/sub sp`,
  `movm`, `call`/`ret`/`retf`/`calls`/`rets`; `opex` and `val` metadata; a
  register profile with the PSW flags, `mdr`/`lir`/`lar`, the AM33 extended
  registers and the FPU registers; ESIL for the integer core, the register-list
  frames and the loops.
* `asm_mn103.c`: pseudo syntax for the common forms.
* `test/test_mn103.c`, `test/test_plugin.py`: decoder, analysis, ESIL and
  emulation checks; `tools/mn103-dis`: binutils-rule linear sweep.
* `README.md`, `doc/mn103.md`.
