# Changelog

## Unreleased

### uSIP table update (475 forms) and decoder rules

* `isa/usip_isa.json` / `usip_opcodes.h`: 475 forms (110 added, 24 retired,
  140 modified). Port I/O `ior`/`iow` replace `mfcr`/`mtcr`; `mtcsr` is back and
  `mfcsr` accepts F' = 0; the `sys` shape is split by its tail field (`cop`,
  `rti`, `lpexit?`, `isync?`, `ieon`, `ieoff`, `trap?`, `sys?`, `ret`, `ret?`,
  `jr?`, `call rB`); `nop32`, `cmov r15`, `add rB, rA, #rot12` for the whole
  op 0 cell, `sne`, `scmp?`, `movhi?`, `extu`, `movi #-1`, `addsp`, `lea?`,
  `st.w [sp+4/12/20]`, `ld.d?`/`st.d?` (64-bit pairs), `st.b?`, the stack-slot
  closers (`ldslot`/`stslot`, `.slot?`, `lsl #1/#2`, `movi #simm6`, `.bit4?`,
  `.ext8?`), `ld.hu` for type 110, unsigned 12-bit ld/st offsets, `ld.bu` in
  the class-E cells, per-operand bank bits (`rB!` by `x`, `rA!` by `m`, `rs1!`
  by `ss`), `save w=2` = four words; the 48-bit `call` with the far tail is
  retired (those packets are `call`/`b` with the F' = 0 tail at +2).
* `tools/gen_usip_tables.py`: `movhi` operand type, `base` as a constant added
  to register/immediate fields, `scale` on immediates, `ge` and `any`
  constraints, membership masks for the large CSR sets, the target guards as
  constraint records, flag `USIP_F_ADJ2`, kinds `io`/`jr`, the `sys` name
  table, extended CSR names, kind names; the header stays reproducible.
* `usip_decode.c`: F' = 0 control tails exactly at +2, target guards evaluated
  after the match (32-bit: failure = `.word`; 16-bit `call.s`: fall-through),
  `packet_len` constraints with the real packet length (stand-alone closers),
  16-bit closers matched with bit 15, rules R0 (the final closer may be its own
  group) and R7 (first-slot `ldslot`/`stslot`/`lea?` when the rest of the
  packet is named), the `1dX6 + named tail` and validated-guard tie-breaks;
  `UsipGuardCtx` lets the caller answer the guards.
* `arch_md32.c`: packet starts for the guards from the session (packets seen)
  and from the bytes at hand (64 bytes of lookahead); function starts are not
  available to an arch plugin, the documented fallback applies (`call?`,
  `beqz.d?`... = unverified, `opex.target_guard`, confidence `medium`); types
  `io`, `rjmp` (`jr?`), `ret` for `rti`, `trap`, `refptr` 8 for the 64-bit
  pairs, `cast` for `extu`; CSR names in `opex`.
* `asm_md32.c`: pseudo syntax for the new mnemonics (`ior`/`iow`, `mfcsr`/
  `mtcsr`, `addsp`, `ldslot`/`stslot`, `jr`, `nop32`, `sne`, `scmp`, `movhi`,
  `extu`, the system ops, 64-bit loads/stores, the `?` marker).
* Tests: `test/test_plugin.py` vectors for `ior`/`iow`, `nop32`, the 32-bit
  `ret`, `jr?`, `addsp`, `ld.d?`, the first-slot slot/`lea?` forms, `movhi?`
  and the guarded 3-unit control packets (validated, failed and unverified);
  `test/test_parse.c` vectors for the new pseudo rules; the `mov32`/`ld.b`
  vectors now show the bank bit of the register it applies to (`r15!`).

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
* `test/test_emulator.py`: in usip mode the probe `5ef9 901a` is a delayed return,
  so the strict stop is `unsupported_delay_slot_execution` (still zero steps).
* Documentation: README "uSIP mode", `doc/usip.md`.
