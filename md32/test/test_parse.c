/* radare2 - LGPL-3.0-only - Copyright 2026 - pancake */
#include <assert.h>
#define R2_PLUGIN_INCORE
#include "../asm_md32.c"

static void check(RAsm *a, const char *input, const char *expected) {
	char *result = r_asm_parse_pseudo (a, input);
	if (!result || strcmp (result, expected)) {
		fprintf (stderr, "%s: got %s, expected %s\n", input, result? result: "NULL", expected);
		abort ();
	}
	free (result);
}

int main(void) {
	RAsm *a = r_asm_new ();
	assert (a && r_asm_plugin_add (a, &r_asm_plugin_md32));
	assert (r_asm_use_parser (a, "md32"));
	check (a, "mv16 r1, -0x1", "r1 = -0x1");
	check (a, "\tmv16\tr1,\tr2  ", "r1 = r2");
	check (a, "mv a0, r1, r2", "a0l = r1; a0h = r2");
	check (a, "sethi r1, 0x1234", "r1 = (0x1234 << 16)");
	check (a, "add r1, r2, r3", "r1 = (r2 + r3)");
	check (a, "add r1, r10, r3", "r1 = (r10 + r3)");
	check (a, "add r0, r0, r0, 0x1", "r0 = (r0 + r0 + 0x1)");
	check (a, "addsp16 r14, -0x4", "r14 += -0x4");
	check (a, "sub16 r1, r2", "r1 -= r2");
	check (a, "and16 r8, r8, 0xffff", "r8 = (r8 & 0xffff)");
	check (a, "or16 r1, r2", "r1 |= r2");
	check (a, "xor16 r1, r2", "r1 ^= r2");
	check (a, "mul r1, r2, r3", "r1 = (r2 * r3)");
	check (a, "sll16 r1, 0x2", "r1 <<= 0x2");
	check (a, "srl r1, r2, 0x3", "r1 = ((uint32_t)r2 >> 0x3)");
	check (a, "sra16 r1, 0x1", "r1 = ((int32_t)r1 >> 0x1)");
	check (a, "clz16 r1, r2", "r1 = clz32(r2)");
	check (a, "clb r1, r2", "r1 = clz32((int32_t)r2 < 0 ? ~r2 : r2)");
	check (a, "max16 r1, r2", "r1 = max_s32(r1, r2)");
	check (a, "min r1, r2, r3", "r1 = min_s32(r2, r3)");
	check (a, "cinv r1, r2, r3", "r1 = ((int32_t)r2 < 0 ? -r3 : r3)");
	check (a, "bclr16 r1, r2", "r1 &= ~(1U << r2)");
	check (a, "bset r1, r2, 0x3", "r1 = (r2 | (1U << 0x3))");
	check (a, "btgl r1, r2, 0x3", "r1 = (r2 ^ (1U << 0x3))");
	check (a, "lb r2, -0x1(r1)", "r2 = sext8(dmem8[r1 - 0x1])");
	check (a, "lbu r2, 0x1(r1)", "r2 = dmem8[r1 + 0x1]");
	check (a, "lh16 r2, -0x2(r1)", "r2 = sext16(dmem16[r1 - 0x2])");
	check (a, "lhu r2, 0x2(r1)", "r2 = dmem16[r1 + 0x2]");
	check (a, "lw r2, (r1+=0x8)", "r2 = dmem32[r1]; r1 += 0x8");
	check (a, "sw r2, -0x4(r14)", "dmem32[r14 - 0x4] = r2");
	check (a, "sb16 r1, (r1+=-0x4)", "dmem8[r1] = r1; r1 += -0x4");
	check (a, "sh r2, 0x4(r1)", "dmem16[r1 + 0x4] = r2");
	check (a, "beq16 0x0, r1, sym.target", "if (0x0 == r1) goto sym.target");
	check (a, "bne r1, r2, 0x1000", "if (r1 != r2) goto 0x1000");
	check (a, "blt r1, -0x1, sym.target", "if ((int32_t)r1 < (int32_t)-0x1) goto sym.target");
	check (a, "bleu r1, r2, sym.target", "if ((uint32_t)r1 <= (uint32_t)r2) goto sym.target");
	check (a, "j16 r15", "return");
	check (a, "j r2", "goto r2");
	check (a, "jal sym.target", "sym.target ()");
	check (a, "nop16", "nop");
	check (a, "mv16.l r1, r2", "r1 = r2");
	check (a, "nop16 | nop16.l", "parallel { nop; nop; }");
	check (a, "xor16 r0, r0 | j16 r15", "parallel { r0 ^= r0; return; }");
	const char *unchanged[] = {
		"", ".word 0x400fd5c0", ".hword 0x8116", "unknown r1, r2",
		"addx r1, r2, r3", "rnds r1, r2, r3", "maxd r1, r2, r3",
		"j16.d2 r15", "beq.d1 r1, r2, 0x1000", "do r1, 0x1000",
		"lw r1, (r1+=0x4)", "lw r1, (r2+=)", "lw r1, 0x4(r2",
		"lw r1, 0x4(r2))", "mv r1,", "add r1,,r2", "add r1,r2,r3,r4,r5",
		"mv r1, r2)", "mv r1, (r2", "save 0x1", "restore 0x1", "b0 0x1000",
		"mv r1, r2, r3", "mv r1, r2 | mv r3, r4 | mv r5, r6",
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (unchanged); i++) {
		check (a, unchanged[i], unchanged[i]);
	}
	r_arch_config_set_cpu (a->config, "usip");
	check (a, "b 0x400e08d0", "goto 0x400e08d0");
	check (a, "b.s 0x1000", "goto 0x1000");
	check (a, "call sym.target", "sym.target ()");
	check (a, "call.abs 0x1ccde9b0", "0x1ccde9b0 ()");
	check (a, "call r2", "r2 ()");
	check (a, "bne r3, #0x1, 0x1000", "if (r3 != 0x1) goto 0x1000");
	check (a, "bltu r1, r2, 0x1000", "if ((uint32_t)r1 < (uint32_t)r2) goto 0x1000");
	check (a, "blt.d r1, #-0x1, 0x1000", "if ((int32_t)r1 < (int32_t)-0x1) goto 0x1000");
	check (a, "beqz r0, 0x14", "if (r0 == 0) goto 0x14");
	check (a, "bz.s r2, 0x4d78", "if (r2 == 0) goto 0x4d78");
	check (a, "ret", "return");
	check (a, "ret.d", "return");
	check (a, "movi r1, #0x230", "r1 = 0x230");
	check (a, "mov32 r15, #0x1d07005c", "r15 = 0x1d07005c");
	check (a, "lsr r15!, r15, #0x1a", "r15! = ((uint32_t)r15 >> 0x1a)");
	check (a, "cmov r0, r1, r2", "r0 = (r1 != 0) ? r2 : r0");
	check (a, "ld.w r0, [r8+0x0]", "r0 = dmem32[r8 + 0x0]");
	check (a, "ld.b r0, [r15+0xa]", "r0 = sext8(dmem8[r15 + 0xa])");
	check (a, "ld.hu r1, [r2-0x4]", "r1 = dmem16[r2 - 0x4]");
	check (a, "ld.w r3, [sp+0x8]", "r3 = dmem32[sp + 0x8]");
	check (a, "st.w r1, [r15+0x4]", "dmem32[r15 + 0x4] = r1");
	check (a, "st.b r1, [r2]+", "dmem8[r2] = r1; r2 += 1");
	check (a, "loop r3, last=0x00002488", "repeat r3 times until last=0x00002488");
	check (a, "save w=0", "push_callee_saved(w=0)");
	// Format-only forms, displaced tails and unmodelled operations keep their text.
	check (a, "st.w [r0], #0x28002", "st.w [r0], #0x28002");
	// system, port I/O, CSR, slot and stack forms of the uSIP table.
	check (a, "mfcsr r15!, #0x01", "r15! = csr[0x01]");
	check (a, "mtcsr #0x20, r4!", "csr[0x20] = r4!");
	check (a, "ior r1, [r2]", "r1 = io[r2]");
	check (a, "iow r1, [r3]", "io[r3] = r1");
	check (a, "jr? r2", "goto r2");
	check (a, "ret?", "return");
	check (a, "rti", "return_from_interrupt");
	check (a, "cop r0", "coprocessor(r0)");
	check (a, "nop32", "nop");
	check (a, "addsp #-0x14", "sp -= 0x14");
	check (a, "addsp #0x10", "sp += 0x10");
	check (a, "ld.d? r0:r1, [r8+0x1f0]", "r0:r1 = dmem64[r8 + 0x1f0]");
	check (a, "st.b? r0, [r11!-0x1]", "dmem8[r11! - 0x1] = r0");
	check (a, "ldslot r0!, #0x1c", "r0! = slot[0x1c]");
	check (a, "stslot r5, #0x3", "slot[0x3] = r5");
	check (a, "lea? r8, [sp+0x14]", "r8 = &[sp+0x14]");
	check (a, "call? 0x000017c0", "0x000017c0 ()");
	check (a, "beqz.d? r4, 0x000007d4", "if (r4 == 0) goto 0x000007d4");
	check (a, "sne r7, r7, #0x0", "r7 = (r7 != 0x0)");
	check (a, "movhi? r9, #0x7ff00000", "r9 = 0x7ff00000");
	check (a, "extu r10, r8!, #0xb, #0x14", "r10 = ((r8! >> 0x14) & ((1 << 0xb) - 1))");
	check (a, "cmov r15, r14!, r0!", "r15 = (r14! != 0) ? r0! : r15");
	// table update: immediate loops, 48/64-bit b<cond>.l, the set-on-compare family, signed 64-bit pairs, the closed
	// negative offsets, the 16-bit first-slot st.h, movhi, jr, the high-bank bit ops and the funnel shift.
	check (a, "loop# #4, last=0x00001c06", "repeat 4 times until last=0x00001c06");
	check (a, "blt.l r2, #0x1, 0x00001582", "if ((int32_t)r2 < (int32_t)0x1) goto 0x00001582");
	check (a, "beq.l? r4, #0x1, 0x00002226", "if (r4 == 0x1) goto 0x00002226");
	check (a, "ble.l?? r4, #0x1, 0x00002226", "if ((int32_t)r4 <= (int32_t)0x1) goto 0x00002226");
	check (a, "bneu.l? r1, #0x3, 0x1000", "if ((uint32_t)r1 != (uint32_t)0x3) goto 0x1000");
	check (a, "sle r4, r9, #0x10", "r4 = ((int32_t)r9 <= (int32_t)0x10)");
	check (a, "sgt r5, r0, #0x190", "r5 = ((int32_t)r0 > (int32_t)0x190)");
	check (a, "ld.d r2:r3, [r9-0xa0]", "r2:r3 = dmem64[r9 - 0xa0]");
	check (a, "st.d r8:r9, [r5-0x24]", "dmem64[r5 - 0x24] = r8:r9");
	check (a, "ld.h r0, [r8-0x32]", "r0 = sext16(dmem16[r8 - 0x32])");
	check (a, "ld.w r2, [r14-0x8]", "r2 = dmem32[r14 - 0x8]");
	check (a, "st.h r8, [r0]", "dmem16[r0] = r8");
	check (a, "movhi r0, #0x00020000", "r0 = 0x00020000");
	check (a, "jr r2", "goto r2");
	check (a, "xor r1, r8!", "r1 ^= r8!");
	check (a, "bset r8!, r0!, #0x0", "r8! = (r0! | (1U << 0x0))");
	check (a, "osl r5, r2, #1", "r5 = ((r2 << 1) | r5)");
	check (a, "mfacc? r7, A0.lo", "r7 = A0.lo");
	check (a, "ldslot r0!, #0x22", "r0! = slot[0x22]");
	check (a, ".unit 0x400a (ld.b @ 0x0000041e)", ".unit 0x400a (ld.b @ 0x0000041e)");
	check (a, ".hword 0xffff", ".hword 0xffff");
	check (a, ".op4imm r0, r1, #0x6", ".op4imm r0, r1, #0x6");
	// table update (634 forms): the bit-field family, nop.ctl, mtacc?, movi? #-32768, the register bset/bext, sgt #-1,
	// addi #32, the lsl / sext16 / zext16 renames, the r15-based loads, the S0F1 branches and the format-only readings.
	check (a, "fxtu r0, r0, #0x1, #0xf", "r0 = ((r0 >> 0xf) & ((1 << 0x1) - 1))");
	check (a, "fxts r2!, r0, #0xf, #0x1", "r2! = sext(0xf)((r0 >> 0x1) & ((1 << 0xf) - 1))");
	check (a, "fup r1, r0, #0x8, #0x8", "r1 = ((r1 & ~(((1 << 0x8) - 1) << 0x8)) | ((r0 & ((1 << 0x8) - 1)) << 0x8))");
	check (a, "fup? r0, r1, #0x1c, #0x4", "r0 = ((r0 & ~(((1 << 0x1c) - 1) << 0x4)) | ((r1 & ((1 << 0x1c) - 1)) << 0x4))");
	check (a, "nop.ctl", "nop");
	check (a, "mtacc? A0, r2!:r4!", "A0 = r2!:r4!");
	check (a, "movi? r8, #-32768", "r8 = -32768");
	check (a, "bset r2, r2, r8", "r2 = (r2 | (1U << r8))");
	check (a, "bext r0, r0, r8", "r0 = ((r0 >> r8) & 1)");
	check (a, "sgt r0, r3, #-1", "r0 = ((int32_t)r3 > (int32_t)-1)");
	check (a, "addi r0, #32", "r0 += 32");
	check (a, "lsl? r0, r0, #0x1", "r0 = (r0 << 0x1)");
	check (a, "sext16 r3, r2", "r3 = sext16(r2)");
	check (a, "zext16? r3, r4", "r3 = (r4 & 0xffff)");
	check (a, "asr16 r1, r2, #10", "r1 = sext16(r2 << 10) >> 10");
	check (a, "ld.h? r8, [r15+0x150]", "r8 = dmem16[r15 + 0x150]");
	check (a, "ld.w? r1, [r15+0x407]", "r1 = dmem32[r15 + 0x407]");
	check (a, "st.w r1, [r8+0x11c4]", "dmem32[r8 + 0x11c4] = r1");
	check (a, "bne.d? r15!, #0x1, 0x00000f1c", "if (r15! != 0x1) goto 0x00000f1c");
	check (a, "beqz.d? r0, 0x0000200c", "if (r0 == 0) goto 0x0000200c");
	check (a, "bleu.d r7, r1, 0x00000e3c", "if ((uint32_t)r7 <= (uint32_t)r1) goto 0x00000e3c");
	check (a, "bne.u8.d r1, #0x3, 0x1000", "if (r1 != 0x3) goto 0x1000");
	check (a, "mov32 r3, #0x7fff7fff", "r3 = 0x7fff7fff");
	check (a, ".ldF0? r0!, [r7+0x240]", ".ldF0? r0!, [r7+0x240]");
	check (a, ".3eX0? r6, 0x6e14 0xd000", ".3eX0? r6, 0x6e14 0xd000");
	check (a, ".op4t0 r0, [r8+0x19]", ".op4t0 r0, [r8+0x19]");
	check (a, ".hi 0x35ff", ".hi 0x35ff");
	// table update (687 forms): the 16-bit shifts in place, ret.s.d, loop.b1?, the R-br0 branches, bz.s with bit 3 = 0, the
	// byte loads/stores, the sp adjustment pair, the ss loops, the BF_SEL cells and the format-only immediate store.
	check (a, "lsl r0, #0x2", "r0 <<= 0x2");
	check (a, "asr? r2, #0xf", "r2 = ((int32_t)r2 >> 0xf)");
	check (a, "ret.s.d", "return");
	check (a, "loop.b1? r5, last=0x0000422c", "repeat r5 times until last=0x0000422c");
	check (a, "loop.b1?? r1?ss=2, last=0x0000261e", "repeat r1?ss=2 times until last=0x0000261e");
	check (a, "bne.u8.d r1, #0x7e, 0x00001b32", "if (r1 != 0x7e) goto 0x00001b32");
	check (a, "bgeu.d r0, #0x2, 0x00000aa0", "if ((uint32_t)r0 >= (uint32_t)0x2) goto 0x00000aa0");
	check (a, "bge.d r0, #0x0, 0x00000652", "if ((int32_t)r0 >= (int32_t)0x0) goto 0x00000652");
	check (a, "bz.s r10, 0x00004f7e", "if (r10 == 0) goto 0x00004f7e");
	check (a, "ld.bu r1, [r8+0x628]", "r1 = dmem8[r8 + 0x628]");
	check (a, "st.b r0, [r14+0x66]", "dmem8[r14 + 0x66] = r0");
	check (a, "ld.b r0, [r0-0xef]", "r0 = sext8(dmem8[r0 - 0xef])");
	check (a, "ld.hu? r0, [r14+0x98]", "r0 = dmem16[r14 + 0x98]");
	check (a, "add r14, r14, #0x4", "r14 = (r14 + 0x4)");
	check (a, "sub r14, #0x1f8", "r14 -= 0x1f8");
	check (a, "ldslot r8, #0x33", "r8 = slot[0x33]");
	check (a, "movi? r2, #-32767", "r2 = -32767");
	check (a, "fxts? r1, r0, #0x8, #0x8", "r1 = sext(0x8)((r0 >> 0x8) & ((1 << 0x8) - 1))");
	check (a, "mtcsr? #0x39, r2!", "csr[0x39] = r2!");
	check (a, "ld.w? r2, [r0!+0x305]", "r2 = dmem32[r0! + 0x305]");
	check (a, ".stimm16? [r0], #0x36688", ".stimm16? [r0], #0x36688");
	r_asm_free (a);
	puts ("MD32 pseudo syntax, Harvard addressing, parallel bundles and conservative fallbacks passed");
	return 0;
}
