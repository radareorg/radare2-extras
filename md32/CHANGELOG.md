# Changelog

## Unreleased

### SCQ16 table update (229 forms), the open-reading marker, the broadcast ports, the confidence levels and the public test vectors

* `isa/scq16_isa.json` / `scq16_opcodes.h`: 229 forms / 402 bit alternatives.
  `jr rn` (6f ec) reads a 5-bit register field (r0-r31); `btst rd, rd, #pos`
  (67 f8-fb) has a 5-bit position; `ctz` is its own form without the
  hypothetical flag, `sqr?` belongs to the `op41` placeholder (hypothetical);
  `and rd, rs, #0x1|#0x3|#0xf` (2 bytes), `add rd, rs, #-1` (2 bytes) and the
  4-byte `sb rd, off(rb)` are `high`, the 4-byte `btst rd, rs, #pos` is `medium`
  (settled by execution results).
* `tools/gen_scq16_tables.py`: the flag `SCQ16_FL_OPEN` (an open reading: a
  family placeholder or a provisional name) and, for an open alternative
  without a template, the uniform ESIL marker `REF,ALT,open`; `export --hyp`
  applies the declared plugin hypotheses of `isa/scq16_hyp.json` and records
  the file's sha256 in the JSON meta and in the header.  The file is empty:
  the packing ESIL / p-code of `op41.fld rd, rs, rt, #pos` is carried by the
  ISA source (still flagged hypothetical), so every ESIL the plugin emits
  comes from the source.
* `scq16_vu.inc.c` / `scq16_arch.inc.c`: the scalar ports `v0-v31` are the
  broadcast ports of the vector register file: a write by `vbcast` /
  `vbcast.i` / `vbcast.i?` reaches the 64 lanes of `vr_k` (an ESIL register-
  write voyeur); the custom op `open` (no effect); `aoj` reports `open`,
  `reading`, `hypothetical` and `confidence` per unit.
* `ctz` of a zero operand: -1 under the table ESIL (`31 - clz(0)`); documented
  as an open question against the hardware (32).
* `asm_md32.c`: pseudo rule of `op41.fld`.
* `test/scq16_vectors.json` + `test/test_scq16_vectors.py`: 195 public
  bytes-only vectors with the expected result in the big-endian regime of the
  harness and in the little-endian regime of the core data memory;
  `test/test_scq16.py` (267 checks) and `test/test_md32.c`: the new forms, the
  marker, the broadcast, the confidence levels, `ctz(0)`.
* `doc/scq16.md`, README: the new forms, the open marker, the broadcast ports,
  the declared limits of the vector unit model, the hypothesis file, the
  confidence levels, `ctz(0)`.

### SCQ16 table update (402 bit alternatives), the `.post` convention and the vector unit model

* `isa/scq16_isa.json` / `scq16_opcodes.h`: 228 forms / 402 bit alternatives.
  `ctz rd, rs` (41 f3 0x22) is an established operation; new provisional
  readings: `sqr? rd, rs` (41 f3 0x23), `sra? rd, rd, #pos` (67 fc-fd),
  `vrd? rd, vb1[x]` (1a xy), `and? #0xf000?` (67 98-9b and the 2-byte 00/01 with
  k = 6), `and? #0xc000?` (67 b4-b7); `op41.fld rd, rs, rt, #pos` reads its third
  field as a register; `lw.post rd, [rb] += 4` (21) has a 4-bit destination;
  the 3-bit post-increment of the `6e` `.post` family is signed; `sra rd, rd, #imm`
  (09) is established; the load templates with a post-increment write rd last
  (with `rd == rb` the loaded value wins).
* `scq16_vu.inc.c` (new) / `scq16_arch.inc.c`: the vector unit model of the ESIL:
  the register file `vr0-vr31` (128 bytes each, four 256-bit quarters in the
  profile), `vp0-vp7` and `va0-va7`; `vop` models `v.mem.ld`, `v.mem.st` and
  `v.move.mv` (loads/stores through the VU pointers with the count of `va[A]`
  and a post-increment, register copies) and leaves every other op9 without effect.
* `asm_md32.c`: pseudo rule of `sqr`.
* `doc/scq16.md`, README: the new forms, the VU model, the `.post`
  convention, the callee-saved profile (r16-r31).
* `test/test_scq16.py`, `test/test_md32.c`: the new forms and the VU model.

### SCQ16 table update (228 forms), the `j.d1` target rule and the vector names

* `isa/scq16_isa.json` / `scq16_opcodes.h`: 228 forms / 400 bit alternatives.
  The exporter (`tools/gen_scq16_tables.py export`) takes the ESIL, the delayed
  transfers (SETJT/SETD) and the hypothetical flag from the form-description
  module itself (its HYP table) and applies no overlay of its own.  Vector
  names: the established operations `v.move.mv`, `v.mem.ld` and `v.mem.st`
  print without the `?` (`vector.firm_op9`), the provisional ones keep it in
  the table string.
  New or renamed: `cmov.ge rd, rs, #imm, ra`, `cmov.eq rd, rs, rx, ra` (the
  register form), the provisional `cmov.leu?` / `cmov.ltu?` / `cmov.lt?` /
  `cmov.le?`, `mv rd, rs` (67 c8), `bset` / `btst rd, rd, #pos` (3 bytes),
  `lbu.post rd, [rb] += inc` with 5-bit registers (6e q2) and the 23 page as
  `lbu.post rd, [rb] += simm3` (-4..-1), `and rd, rs, #0x3fff` (67 a4-a7), the
  6-byte `and rd, rs, #imm16` (74 sub 1), the provisional `ctz?` / `clb?` (41 f3),
  `vcfg4c? v, rs, #0xc` with the hypothetical `p_k <- rs`, `ld46?` as a
  hypothetical byte load with a post-increment, `lbu? rd, off(sp)` (ex `lb?`),
  `addsp sp, #imm` (14 8x-fx), `fxts` without the `?`; `halt` and `sys41` carry
  the empty ESIL (no modelled effect); `5c 40-6f` is the 4-byte `beq rA, rB`.
* `scq16_decode.c`: `j.d1 56 0x-3x` decided by its target (stand-alone units
  and B slots); every ESIL memory access cuts its address to 32 bits (negative
  frame offsets wrapped in the 64-bit ESIL machine); the `?` of a vector name
  comes with the table string.
* `scq16_arch.inc.c`: a unit with the empty ESIL no longer blocks the ESIL of
  its packet; opex `named` / `provisional` of vector ops follow the table name.
* `asm_md32.c`: pseudo rules of `cmov.ge`/`cmov.leu`/`cmov.le`, `sys41`, `ctz`/`clb`.
* `tools/scq16_flags.r2`: the data-space bases (DM, I/O window, DM2) as flags.
* `test/test_scq16.py`, `test/test_md32.c`: the new forms, `j.d1` by target,
  `.d2` across two `aes` steps, negative stack offsets, the vector names.

### SCQ16 mode (cpu=scq16): the table (218 forms), the byte-granular packet decoder, analysis and ESIL

* `isa/scq16_isa.json` / `tools/gen_scq16_tables.py` / `scq16_opcodes.h` /
  `scq16_decode.c`: the SCQ16 (MD32 family, byte-granular packet variant) as
  a third cpu of the plugin: 218 forms / 389 bit alternatives generated from
  the ISA table, which carries the plugin semantics (the VU ports as
  registers, delayed transfers as SETJT/SETD, the hypothetical readings
  flagged), the length rule by first-byte leaves, packets `{ A ‖ B }` with
  the head shifted by the borrowed bit, masked orphans, 4-byte vector ops by
  op9 class (v.<class>[.<name>?]) and 8-byte bundles.
* `arch_md32.c` / `scq16_arch.inc.c`: analysis (types, targets relative to the
  packet start, delay slots counted in instructions, `do` as a loop
  reference, opex with the unit/packet/bundle structure), ESIL for the scalar
  forms with parallel packet semantics (temporaries t0-t3), delayed transfers
  via SETJT/SETD, the VU scalar ports as registers (vu*, v*, va*, vp*, vs*,
  vb1_/vb3_/vb5_*, udf*) and vector ops as the custom op `vop`; register
  profile with sp/lr as csr14/csr15, a0 and the loop registers; byte alignment,
  MAXOP 12.
* `asm_md32.c`: SCQ16 pseudo-syntax (packets as `parallel { ...; ...; }`).
* `test/test_scq16.py`, `test/test_md32.c`: bytes-only checks of cpu=scq16.
* `doc/scq16.md`, README "SCQ16 mode".

### uSIP table update (760 forms), the parallel packet, the 22-bit branches and the slot pairs

* `isa/usip_isa.json` / `usip_opcodes.h`: 760 forms (46 added, 12 retired,
  41 modified). The packet executes in parallel and every read sees the
  state before the packet (`structure.packet.execution`,
  `USIP_PACKET_EXEC_PARALLEL`; no decoding rule depends on an intra-packet
  order). New: `movi rB, #imm17` (the op 7 head with the null-field tail, a
  17-bit rotated immediate; `movi_min16` / `movi_m32767` retired: with m = 0
  their value was -65536 / -65535), `movhi` with the small F' = 0 tails
  (`c001` = 0x10000000, even f12 = 0x1000..0x7000), the 16-bit `ld.w rB,
  [rA -/+ 4]` of the first slot and the one-unit `st.w rB, [rA -/+ 4]`,
  `addi rA, #-4 / -2 / -1` of the class-E cell, `loop rX, last, x16` (B = 1,
  the former `loop.b1?`), the guard `loop_b4_straddle16` on the twelve
  `loop #N` entries (bit 4 of the head must agree with "the packet at the end
  crosses a 16-byte line") and the `loop #N?` rule
  (`structure.packet.loop_imm_q`: N = 0 or the end at pc + 2^k), the m = 1
  `loop #N` without the `?`, the 22-bit displacement of every `b<cond>.l`
  (`U1[7:0] : T[13:12] : T[11:0]`: backward and +4096..+8191 cells) and the
  fifteen `bcc48_*_64x` entries (the 64-bit variant whose extension unit is
  any 16-bit unit X, with the guard `not_over_validated_call32`), the op c
  F = 1 branches with the F' = 0 tail exactly at +2 (`beqz_F0c` / `bnez_F0c` /
  `bleu_rr_F0c` / `bltu_rr_F0c`, `ctx:tail_at_plus2`) and the op 9 F = S = 0
  cell of >= 4 units (`bne_imm8_F0s0` / `blt_imm8_F0s0`), `bz.s` with the P4
  cell F = 0 in 2- and 3-unit packets (`bz_s_P4_F0`), the slot pairs
  (`stslot_F0_k16`, the op c pairs `stslot_slotc_h / _t` and their `stslot?`
  twins, `ctx:slotc_pair` / `ctx:call_within_2_packets`, `ctx:op4imm_head` on
  `stslot_F0_q`, `ldslot_S0_pos1` without the `?`), the fusion at distance 2
  `add rB, rA, #rot12` (`add2_rot12`, `fuse_pair` + `tail_adjacency` 2),
  `ld.h / ld.hu` with the F' = 0 tail at +2 and any base (`rf0dall_ld_h /
  ld_hu`, `ctx:rf0dall_guards`), `saturate`, `mfacc` of the C cell and
  `sext16 / zext16` with S = 0 without the `?`; the CSR names `ag0-ag3.{base?,
  len?, idx?}` for 0x30-0x3e; the score rules lr32 / rr7 / spodd / rf0dall
  nowaw in `structure.packet.tie_breaks`.
* `tools/gen_usip_tables.py`: the guards `loop_b4_straddle16` (exported with
  the head field `b4`) and `not_over_validated_call32`, seven new context
  conditions, `FUSE | ADJ2` for the fusion at distance 2, the constants of the
  packet model and of the `loop #N?` rule.
* `usip_decode.c`: slotpair0 before the layout, the 22-bit prefix
  displacement and the 64-bit X variant (the branch keeps U0 U1 T, X is the
  first instruction of the delay slot; the guard against a validated 32-bit
  call / b of U0 + X), the straddle guard of `loop #N`
  (`UsipGuardCtx.packet_units`) and the `loop #N?` text, `ctx:tail_at_plus2`
  (fall-through, never `.word`; the fallback pairs carry their distance),
  the rf0dall guardians in the f0ctx pass, `bz.s` of the P4 cell F = 0, the
  post rules R-add2 (`.hword` heads only) / R-fslot0c before the split pass
  and after the prefix paths, R-slotc in the split pass and `slotc_mark`
  after the packet (the two following packets through `packet_at`), the
  F-slot0 readings by rule, the score rules lr32 / rr7 / spodd / rf0dall
  nowaw. Unverified policy: the `loop_imm_F1S0` reading is no longer
  accepted (wrong too often), the R-F0c / R-F0s0 branches are (right in
  nearly every case), the `b<cond>.l` prefix forms only in their forward cell
  below 4096 units (the 22-bit cells and the X variant need the target
  validated), the x16 loops as the other `loop rX`.
* `arch_md32.c`: the `packet_units` callback (the units of the packet at the
  loop end, from the bytes at hand or the session's cache; an eight-unit run
  without a closer is unknown).
* `asm_md32.c`: pseudo syntax for `loop rX, last, x16` and `saturate`.
* Tests: `test/test_plugin.py` vectors for the parallel packet, `movi #imm17`,
  the small `movhi` cells, the 16-bit `ld.w` / `st.w` with +-4, the class-E
  `addi`, `loop x16`, `loop #N` with the straddle guard (accepted and
  rejected), `loop #N?` (validated and unverified), the backward 22-bit
  `b<cond>.l` (validated and `.word`), the 64-bit X variant (validated and
  fallback), `beqz` of R-F0c (validated and unverified), `blt.d` of R-F0s0
  (validated and fallback), `bz.s` of the P4 cell F = 0 (2 and 3 units,
  validated and unknown), slotpair0, the op c slot pairs with and without a
  call, R-fslot0c, R-add2 and rf0dall; the `loop`, `asr16`, `ld_h_Fp0`,
  `movi #-32768 / #-32767`, `loop.b1?`, `loop #256?`, `ldslot?`, `stslot?`
  and `saturate?` vectors updated to the new readings; `test/test_parse.c`
  vectors for the new pseudo rules.

### uSIP table update (726 forms), the loop cells and the slot splits

* `isa/usip_isa.json` / `usip_opcodes.h`: 726 forms (52 added, 13 retired,
  14 modified). New: the `loop #N` count is the collected head field (bits
  13:5, no +1), `loop #N` with the F' = 0 tail exactly at +2
  (`loop_imm_*_F1_Fp0`), with h = 1 (N >= 128) and with m = 1 (N >= 256,
  printed `loop #N?`), `bz.s` in 4- and 3-unit packets (`bz_s_P4_u4` /
  `bz_s_P4_u3`), the split entries of the slot family `stslot` / `stslot?` /
  `ldslot?` (F-slot0, S0-slot, the S3 cells `ldslot/stslot #48-63`;
  `split_role`), the fusion entry `op72? rA, #k, asr#b` (`fuse_pair`),
  `op2z? rA`, `lsl/asr r8-r15, #B`, the W6 cells `ld.h/st.h rB, [r8+rrr]` and
  `[rA]+` with h = 1, `sub r14, #f12/2` with any F/F' (`spfix_sub_sp`
  retired), `st.w [sp], #imm14`, `st.abs` with the hi F' = 0, `add rB, rB,
  #imm27` / `st.h? [rB], #sat` selected by the immediate value (also the
  cell-E triples), `add? rB, r15, #rot12` and `ld.h? / ld.hu? rB, [r15+off]`
  with the F' = 0 tail, `saturate? rd, rs1`, `movi #simm6` in the delay slot
  of a validated branch, `mtcsr #0x30-0x3e`, `ld.h / ld.hu / lea / movi
  #-32768 / #-32767 / ld.hu [rA+rB]` without the `?` (twelve `*_q` ids
  replaced); the constraints `any(rA != 14, m == 1, tail_adjacent == false)`
  on `beq_imm8_d` (the op 9 `beq.d` with base sp and the adjacent tail is
  not a branch) and `any(m == 1, rA >= 8, x == 0, rB != 15)` on the seven
  op a `*_s0f1` / `*_imm8_F0` entries (the `bgt rA, #-1` head class takes
  only the adjacent S = 1 tail); the ABI passes eight arguments in r0-r7.
* `tools/gen_usip_tables.py`: the flags `FUSE`, `SPLIT` / `SPLITBARE` (with a
  `USIP_FORM_*` index for every split and fusion entry), the constraint op
  `instr_index`, `any` with up to four alternatives that may be a context
  condition or an instruction position, six new context conditions; the
  `loopn` operand type is the collected field.
* `usip_decode.c`: the score in twentieths (al1 = 0.3), the explicit
  candidates loopcand / R-brHHTT / R-b111pre / R-b111ctl with the
  `b111_layout` context extended to them, the `bz.s` rules of 4- and 3-unit
  packets (the rest re-parsed as the delay slot, the 3-unit one with the
  target beyond the packet and no write of rA), the S3 renames and the split
  pass of the slot family with the split-tail reading and the nowaw guardian,
  the fusion after the renames, R-movi6d, the R-w6h1 loop guard evaluated
  with the packet being parsed, the R-loopA adjacency (`.word` at any
  distance but +2), rf0dmidwaw, the score rules R-waw / al1 / R-bsnext /
  P2W-P2H prefix / sat40 H H T T / rf0dpen, the instruction position of the
  renames. Unverified fallback: the loop entries with the F' = 0 tail at +2
  and the h = 1 heads with the S = 1 tail (and the adjacent F = 0 tail) are
  accepted; the m = 1 (`loop #N?`) and the other h = 1 entries are not (wrong
  too often when unverified).
* `arch_md32.c`: the stores of an immediate (`[rB]` / `[sp], #imm`) carry the
  value in `val` and `[sp]` the stack access; the new mnemonics keep their
  kinds (`op2z?` / `op72?` / `saturate?` are unknown operations).
* `asm_md32.c`: pseudo syntax for the stores of an immediate (also to `[sp]`),
  the absolute `st.abs` / `ld.abs`, the `?` of a count (`loop#? #256?`).
* Tests: `test/test_plugin.py` vectors for the loop count, the F' = 0 / h = 1 /
  m = 1 loops (validated and unverified), the 4- and 3-unit `bz.s` (validated
  and unknown), beq9sp, the `bgt rA, #-1` cell, the W6 h = 1 cells and the
  loop guard, `op2z?`, the h = 1 shifts, the 16-bit `lea`, the splits
  (R-slot4n, R-op4imm in 2 and more units, S0-slot, S3), `op72?`,
  `saturate?`, sat40 H H T T, R-waw with the P2W prefix, R-b111pre,
  R-b111ctl, R-bsnext, the omitted weak cell of R-brHHTT, `sub r14`,
  `st.w [sp]`, `st.abs` hi F' = 0, addq / cell E by value, `mtcsr` of the
  accumulator CSRs, R-1eX0F0, R-movi6d; the `lea`, `loop#`, `mtcsr`, `movi
  #-32768 / #-32767`, `ld.h` / `ld.hu` of R-1eX0 / R-ldF0 / R-hhttF0 / R-F0d,
  `op2z?` and two R-waw vectors updated to the new readings;
  `test/test_parse.c` vectors for the new pseudo rules.

### uSIP table update (687 forms), the target filter and the F = 0 branch cells

* `isa/usip_isa.json` / `usip_opcodes.h`: 687 forms (56 added, 3 retired,
  71 modified). New: the `b<cond>.d` cells with head F = 0 (`bne.d`, `ble.d`,
  `bgeu.d`, `bge.d`, `bne.u8.d`, `beq.u8.d`, `bleu.d`, read only in the
  (B class, tail distance) cells of `usip_br0_cells[]`; the five weak cells of
  `usip_br0_cells_weak[]` are never taken), `bgt.d` of the F = S = 0 cell back
  in the table, `ret.s.d`, `loop.b1? rX, last=` and the `?ss=N` loops, `bz.s`
  with bit 3 = 0, the ld/st type 111 `ld.bu` / `st.b` (`st.b?` retired) with
  the byte displacement `sext12(f[0]:f[10:1]:f[11])` (`USIP_A_OFFB`, also on
  `ld.b`), `ld.b` / `st.h` with F != S of op 1 exactly at +2, `ld.h?` / `ld.hu?`
  with the F' = 0 tail as the second head of H H T T and by the deferred tail
  of a head with base sp (context group `f0ctx`), the bit-field pair
  `fxtu`/`fxts`/`fup` in H H T T and the BF_SEL cells
  `fup`/`fup?`/`fxtu`/`fxtu?`/`fxts?` (renamed from `.bf?` with the nowaw
  guardian), the 16-bit op 2 shifts `lsl`/`lsl?`/`asr`/`asr? rA, #B` (`addi4`
  retired), `ldslot`/`stslot` with m = 1, `.stimm16?`, `ld.w?`/`st.w?` for the
  `f12 = 1 / 3 mod 4` word classes, `add r14` / `sub r14` (spfix),
  `movi? #-32767`, `movi rA, #-1` with F = 0, `mtcsr?` of the accumulator CSRs
  with a named 16-bit tail; the known target as a validation filter on the
  F = S = 0 cells, `bne.d #-1`, the loops with the F' = 1 tail, the open `b.s`
  (also a function start) and the near `b` (any packet start of the image or a
  function start), with fall-through on failure for the F = S = 0 cells
  (`USIP_F_GUARDFT`); the operand conventions of six families revised
  (`mul`/`divs`/`divu`/`mulu64 A<k>, r<rrr>, rB`, the op 7f bit ops,
  `cls1`/`clz`/`ctz`, the op 6 compare-immediates, the 48-bit `add`, `asr16`);
  `known16 = false` on the four h = 0 word slots. Thirty-one entries are
  post-layout renames.
* `tools/gen_usip_tables.py`: the operand type `offb`, the flags `GUARDFT` /
  `B111` / `F0CTX` (`flags` is `ut32`), the constraint ops `br0_cells` /
  `br0_cells_live` (cell masks), `bf_valid`, the guards `tail_named16` and
  `target_packet_start_any_or_function_start`, the `any` sub-operations
  `packet_len`, `guard`, `range`, `br0_cells`, large value sets
  (`usip_value_sets[]`), the new context conditions, the tables
  `usip_br0_cells[]`, `usip_br0_cells_weak[]`, `usip_c48sym_table[]`; form
  names sanitised into C identifiers.
* `usip_decode.c`: the fall-through guards, the fifth guard kind with the
  optional `UsipGuardCtx.packet_start_any` callback, the R-br0 cells by B class
  and tail distance, the `b111` group in the 2-unit packet and in H H T T (which
  now takes tt = 11 tails), the context conditions `b111_layout` /
  `hhtt_second_head` / `f0d_triple` / `bfpair` / `bf_dst_not_written` /
  `rest_named_no_q`, the `f0ctx` pass on the `.word` pairs and the re-read of
  the R-F0d middle unit, R-op1fs (a ld/st entry with `ADJ2` undoes the pair at
  any other distance), the `bz_s_P5` context rule, the m = 1 R7 slots, P2H,
  R-lr16, R-align48 and R-c48sym in the score, the `b.s` guard admitting a
  function start, the loop F' = 0 rule by field; immediates glued to a letter
  or `=` (`A0`, `?ss=2`, `w=0`) printed in decimal. Unverified fallback: the
  forms whose guard is a validation filter keep their reading when the target
  is unknown (`b.s?`, `b?`, `loop?`, `bne.d?` ...; conditional branches only
  forward), a definite "not a packet start" rejects them.
* `arch_md32.c`: `UsipGuardCtx` with designated initialisers; the lowest packet
  start decoded in the session separates "not a packet start" from "unknown"
  for backward targets; `offb` as a `disp` operand in `opex`; stack deltas for
  `addsp` and the `add r14, r14, #imm` / `sub r14, #imm` pairs.
* `asm_md32.c`: pseudo syntax for the 2-operand `lsl` / `asr`.
* Tests: `test/test_plugin.py` vectors for the F = S = 0 and R-br0 cells
  (validated by the session, rejected with fall-through, unknown backward,
  unverified forward), `ret.s.d`, `movi #-1` F = 0, the op 2 shifts, the open
  `b.s` rejected / unverified, `bz.s` P5 (2-unit, validated, unknown), the m = 1
  slots, `loop.b1?` and the `?ss=N` loops, `movi? #-32767`, the `asr16` clamp,
  the bit-field pair and the BF_SEL cells, `ld.bu`/`st.b` with the byte
  displacement (plain, 2-unit b111, H H T T), `ld.b`/`st.h` F != S at +2 and
  the undo at +1, `ld.h?`/`ld.hu?` of R-hhttF0 / R-F0d, spfix, NEGQ,
  `.stimm16?`, `mtcsr?` with a named tail; the `loop`, open `b.s`, `mtcsr`,
  `movhi` tt = 10 and `save w=` vectors updated; `test/test_parse.c` vectors
  for the new pseudo rules.

### uSIP table update (634 forms), decoder rules and the K-tie cascade

* `isa/usip_isa.json` / `usip_opcodes.h`: 634 forms (52 added, 12 retired,
  103 modified). New: the 14-bit word displacement of the two-unit
  `ld.w`/`st.w` (W14: `f12 = 2 mod 4` is `+0x1000 + (f12 & ~3)`), `nop.ctl`
  for `5e0d`/`1e0d`/`de0d` (never a tail, never a head with a tail), the
  bit-field family `fxtu`/`fxts`/`fup`/`fup? rB, rs1, #w, #pos`,
  `movi? rB, #-32768`, the register forms `bset`/`bext rd, rs1, rB`, `mtacc?
  Ak, rs1:rB` (was `clr.a?`), `sgt rB, rA, #-1` with F = S = 1, `addi rA,
  #32` next to `cop rA`, the 16-bit `lsl`/`lsl?`/`sext16`/`zext16` variants,
  `ld.w?`/`ld.h?`/`ld.hu? rB, [r15+off]`, `.ldF0?` and the F' = 0 `ld.h?`/
  `ld.hu?`, `.3eX0?`, the 20 `b<cond>.d` cells with the `[0][1][tt]` tail at
  +2, `movhi` with the tt = 10 tail (IEEE test), 16 non-canonical 48-bit
  constants admitted by a value table, the double-class split (`.op4t0`,
  `.movi6?`, `.st.h?`/`.st.b?`/`.ld.h?`/`.ld.b?`, `ld.sp`); retired the
  `.hi`/`.hilo` pair entries and every `not_hi1010` constraint (H1: a
  hi(1010)-shaped unit is an ordinary head unless a 48-bit instruction claims
  it), `osl_0_15_2`, `clr.a?`. Twenty entries are post-layout renames
  (`rename_from`).
* `tools/gen_usip_tables.py`: `rename_from` lists per entry, the constraint
  ops `tail_adjacent`, `ieee_short` and the 48-bit value table membership, the
  `any` sub-operation `tail_adjacent`, the context conditions
  `cop_rA_in_packet` / `not_c48_lo_follows`, `USIP_MAXVALS` 12, the tables
  `usip_never_tail`, `usip_never_head_with_tail` and `usip_c48_table`; the
  rename entries are exempt from the 16-bit position-class checks.
* `usip_decode.c`: W14, the never-tail and never-head-with-tail units from the
  tables, H1 (the forced hi(1010) decode is gone; `.hi`/`.lo` only after a
  48-bit-family head in the packet), the 48-bit value table in the partial
  admission, P2W (no alignment penalty for the `= 2 mod 4` word offsets in the
  H H T T layout), callin (`UsipGuardCtx.inside_function`), the post-layout
  renames (`apply_renames`), the K-tie cascade (`dedup` and `nowaw` over the
  tied readings of the packet; `du2` over the neighbouring packets the caller
  supplies through `UsipGuardCtx.packet_at` / `branch_target`, first-pass
  readings with `USIP_GUARD_NO_CASCADE`), `UsipPacket.tiebreak`; the failed op
  C compare-and-branch guard is printed `.dsp` (unnamed data either way).
  Unverified fallback extended to the S0F1 cells whose unverified readings are
  right in nearly every case (`bne`/`blt`/`bgeu`/`bgtu`/`bge` with immediate,
  `beqz.d`/`bnez.d`, `bleu` register) and to `loop rX` with the F' = 0 tail
  when the head has F = 1 and the S = 1 tail sits at +2.
* `arch_md32.c`: the cascade context (packets decoded earlier in the session,
  first-pass readings of the packets inside the bytes at hand, the branch
  targets seen so far), `opex.packet.tiebreak`, `ireg` = `r15` for the r15-based
  loads, types for `fxtu`/`fxts` (`cast`) and `fup` (`or`).
* `asm_md32.c`: pseudo syntax for `fxtu`/`fxts`/`fup`, `mtacc`, the 2-operand
  `addi`, `sext16`/`zext16`, `asr16`; `nop.ctl` reads `nop`.
* Tests: `test/test_plugin.py` vectors for W14, `nop.ctl`, the bit-field
  family, `mtacc?`, `movi? #-32768`, `sgt #-1`, the register `bset`/`bext`, the
  S0F1 branches (unverified, validated by the session, not validated), the
  r15-based loads, `.ldF0?`, the F' = 0 `ld.h?`, the 48-bit value table,
  `.3eX0?`, the `lsl`/`sext16`/`zext16` renames, `cop ‖ addi`, `.hi`, `movhi`
  tt = 10, `.op4t0`; the op8 slot split vector updated; `test/test_parse.c`
  vectors for the new pseudo rules.

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
