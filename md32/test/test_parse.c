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
	check (a, "save w=0x0", "push_callee_saved(w=0x0)");
	// Format-only forms, displaced tails and unmodelled operations keep their text.
	check (a, "st.w [r0], #0x28002", "st.w [r0], #0x28002");
	check (a, "mfcsr r15!, #0x01", "mfcsr r15!, #0x01");
	check (a, ".unit 0x400a (ld.b @ 0x0000041e)", ".unit 0x400a (ld.b @ 0x0000041e)");
	check (a, ".hword 0xffff", ".hword 0xffff");
	check (a, ".op4imm r0, r1, #0x6", ".op4imm r0, r1, #0x6");
	r_asm_free (a);
	puts ("MD32 pseudo syntax, Harvard addressing, parallel bundles and conservative fallbacks passed");
	return 0;
}
