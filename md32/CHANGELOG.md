# Changelog

## Unreleased

### uSIP mode rewritten as a table-driven VLIW packet decoder

* `isa/usip_isa.json`: the instruction table (386 forms with masks, operand
  fields, constraints and a confidence level) and the packet model;
  `tools/gen_usip_tables.py` generates `usip_opcodes.h` from it.
* `usip_decode.c`/`.h`: packet decoder (16-bit unit scan, packets closed by
  bit 15, heads-first/round-robin head-tail pairing per group, slot-0-only
  control flow, delay slot = rest of the packet, 48-bit forms with hi/lo units,
  documented tie-breaks and context rules).
* `arch_md32.c` (`cpu=usip`): one op per run of adjacent units of the same
  instruction, `.unit` ops for displaced tails, packet cache in the session,
  analysis types/conditions/targets/delay/fail for the whole control-flow
  family, loads/stores and immediates, `opex` with form/confidence/packet info,
  a register profile with the ABI, `MAXOP_SIZE` 16 in this mode. The previous
  five hard-coded patterns (`b0`-`b7`, `save16`, two call shapes) are replaced
  by named conditions and the table.
* `asm_md32.c`: pseudo syntax for the uSIP mnemonics (`#` immediates, `[base+off]`
  memory operands, compare-and-branch, `save`/`restore`, `loop`).
* `test/test_plugin.py`: uSIP packet vectors (control flow in slot 0, delay
  slots, interleaved `S S O O` layout, 48-bit forms, hardware loop, context
  rule, truncated packet); `test/test_parse.c` updated for the new mnemonics.
* Documentation: README "uSIP mode", `doc/usip.md`.
