# Changelog

## Unreleased

### uSIP table update (594 forms) and the prior-free packet parser

* `isa/usip_isa.json` / `usip_opcodes.h`: 594 forms (137 added, 18 retired,
  76 modified). New: the 48/64-bit compare-and-branch prefix forms
  `b<cond>.l rB, #imm9 / rA, target` (complete condition table incl. the
  unsigned cells and the 64-bit twin with the `1e0d` unit), `loop# #N, last`,
  the op 6 set-on-compare family `seq`/`sle`/`slt` and `sgt rB, rA, #rot10`,
  `movhi` with the 20-bit value and the small cell, `movi?` for the op b class,
  the 48-bit `mov32`/`add` constants by one formula, `st.w`/`st.h [rB], #imm`,
  the cell-E triple by position, `ld.d`/`st.d` with the signed offset, the
  closed negative half-word (`f12 - 0x1001`) and word (`4*sext10(f12 >> 2)`)
  offsets, `add rB, rA, #rot12` for the odd f12 cell, `st.h` with the F' = 0
  tail (deferred), the 16-bit first-slot `ld.h`/`st.h`, `movi rA!, #imm5`,
  `xor rA, rB` alone, the position cells `ld.w?` (k = 0) / `mfacc?` (k >= 2),
  6-bit `ldslot`/`stslot` and the `.op8?` split, `bset`/`bclr?`/`binv?`/`bext?
  rd!`, `osl`, `jr rB`, the `sys` twins with F = S = 0, the H H T T loads/
  stores, the bank bit of the compared register of the 32-bit branches;
  retired `trap?`, `beqz.l`, `jr?`, `movhi?`, `ld.d?/st.d?` (now `ld.d`/`st.d`),
  `.ld.abs`, `movi_max32`/`movi_sext27`/`add_r15_imm27` (now `mov32`/`add`),
  `sgn?`/`scmp?` (now `sgt`), `bgt.d` of op a.
* `tools/gen_usip_tables.py`: operand types `offh`/`offw`/`loopn` and the
  redefined `movhi`, flags `USIP_F_ADJDEF`/`PREFIX`/`RENAME`/`HHTT`, 8 bit
  ranges per field, 64-bit entries, constraints `gt`, `odd`, `packet_len_ge`,
  `head_index`/`head_pos_ge`, `ctx`, the guard `head_not_validated_bs`, `any`
  with up to three alternatives incl. set membership, the `bcc48` condition
  table, `save w=4` = `{LR, r8}`.
* `usip_decode.c`: the prefix forms matched on the first units before the
  layout (failing guard = not taken), the prior-free total order
  `(s0, I, Fv, -A, K)` replacing the enumeration order and the group count,
  the grammar rules (`5e0d` never a tail, the deferred `st.h` tail with its undo
  and the validated-`b.s` guard, the `.d` SP-negative rejection, the 3-unit and
  H H T T explicit candidates with the forced decode of hi(1010) heads, the
  `0e10 3fc0 c000` trio, the `loop #N` F = 1 adjacency, the op8 slot split), the
  alignment exception `f12 = 3 mod 4 >= 0xf00`, the +0.5 add relabel, +1.0
  identical units, +0.75 store-of-immediate triples and +0.5 mfcsr pair
  penalties, the position cells (deferred `head_index`/`packet_len`/`ctx`
  constraints with fall-through), the late guard evaluation with the undo of a
  pair, three tails for the 64-bit forms. Unverified fallback extended to the
  prefix forms and to `loop #N` (F = S = 1, F = 0 with the tail adjacent, F = 1
  with the S = 0 tail at +2).
* `arch_md32.c`: conditions `bequ`/`bneu`, types for `sle` (`cmp`) and `osl`
  (`shl`), `val` = N for `loop #N`, the signed offsets as `disp` operands in
  `opex`.
* `asm_md32.c`: pseudo syntax for `loop#`, `sle`, `bequ`/`bneu`, the 2-operand
  `xor`, `mfacc`, `bset`/`bclr`/`binv`/`bext`, `osl`; the `?` marker stripped
  repeatedly (`ble.l??`); `ld.d`/`ld.w` no longer sign-extended.
* Tests: `test/test_plugin.py` vectors for `loop#` (validated at +1 and +2,
  unverified), `b<cond>.l` (validated, unverified, not taken, 64-bit),
  `ld.d`/`st.d` with a negative offset, the negative half-word and word offsets,
  `seq`/`sle`/`sgt`, `movhi`, the 16-bit first-slot `st.h`, the deferred `st.h`
  and its undo by a validated `b.s`, H H T T, the op8 split, the `0e10` trio,
  `cop` with F = S = 0, `xor`, `movi rA!`, `bset rd!`, `osl`; the `jr`, `ld.d`,
  `movhi` and bank-bit (`bnez r15!`, `beqz.d r2!`) vectors updated;
  `test/test_parse.c` vectors for the new pseudo rules.

### MS15E30: `cmulr16`/`cmuli16` names

* `md32_opcodes.h`: the names of 0xDA00 (`cmulr16`, a*c - b*d) and 0xDC00
  (`cmuli16`, a*d + b*c) follow the little-endian layout of the data memory (the
  high half of a 32-bit complex word is at +2 and holds the real part); the
  earlier assignment assumed a big-endian data memory. Vectors in
  `test/test_md32.c` and `test/test_plugin.py`.

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
