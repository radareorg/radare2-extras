/* radare2 - GPL-3.0-or-later - Copyright 2026 - n0p */
/* Unit checks of the decoder and the analysis through the plugin's decode callback. */
#include <r_anal.h>
#define R2_PLUGIN_INCORE 1
#include "../arch_mn103.c"
#include <assert.h>

static RArchConfig config = { .bits = 32, .endian = R_SYS_ENDIAN_LITTLE };
static RArchSession session = { .config = &config };

static bool run(RAnalOp *op, const ut8 *bytes, int size, ut64 addr, const char *cpu, unsigned mask) {
	r_anal_op_init (op);
	op->bytes = (ut8 *)bytes;
	op->weakbytes = true;
	op->size = size;
	op->addr = addr;
	config.cpu = (char *)cpu;
	return decode (&session, op, mask);
}

static int hexbytes(const char *hex, ut8 *out, int max) {
	int n = 0;
	while (hex[0] && hex[1] && n < max) {
		unsigned v;
		if (sscanf (hex, "%2x", &v) != 1) {
			break;
		}
		out[n++] = (ut8)v;
		hex += 2;
	}
	return n;
}

static void check_cpu(const char *cpu, const char *hex, const char *text, int type, ut64 addr) {
	ut8 bytes[8] = { 0 };
	const int n = hexbytes (hex, bytes, sizeof (bytes));
	RAnalOp op;
	const bool ok = run (&op, bytes, n, addr, cpu, R_ARCH_OP_MASK_ALL);
	if (!ok || !op.mnemonic || strcmp (op.mnemonic, text) || op.type != (ut32)type || op.size != n) {
		fprintf (stderr, "%s: got %s (type %d, size %d, ok %d), expected %s (type %d, size %d)\n",
			hex, op.mnemonic? op.mnemonic: "(null)", op.type, op.size, ok, text, type, n);
		abort ();
	}
	r_anal_op_fini (&op);
}

static void check(const char *hex, const char *text, int type) {
	check_cpu ("am33-2", hex, text, type, 0x1000);
}

static void check_esil(const char *hex, const char *esil) {
	ut8 bytes[8] = { 0 };
	const int n = hexbytes (hex, bytes, sizeof (bytes));
	RAnalOp op;
	assert (run (&op, bytes, n, 0x1000, "am33-2", R_ARCH_OP_MASK_ALL));
	const char *got = r_strbuf_get (&op.esil);
	if (strcmp (got, esil)) {
		fprintf (stderr, "%s: esil %s, expected %s\n", hex, got, esil);
		abort ();
	}
	r_anal_op_fini (&op);
}

static void check_invalid(const char *hex) {
	ut8 bytes[8] = { 0 };
	const int n = hexbytes (hex, bytes, sizeof (bytes));
	RAnalOp op;
	assert (!run (&op, bytes, n, 0x1000, "am33-2", R_ARCH_OP_MASK_ALL));
	assert (op.type == R_ANAL_OP_TYPE_ILL && op.size == 1);
	r_anal_op_fini (&op);
}

static void length_rule(void) {
	/* every first byte has a length, and the table rows agree with it */
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (mn103_opcodes); i++) {
		const Mn103Opcode *op = &mn103_opcodes[i];
		const int size = mn103_format_size (op->format);
		int shift = 8 * (size >= 4? 4: size) - 8;
		const ut8 b0 = (ut8)(op->opcode >> shift);
		int rule = mn103_insn_size (b0);
		if (rule == 7 && (op->opcode & 0xfff80000) == 0xfe800000) {
			rule = 5;
		}
		if ((b0 & 0xc0) == 0x80 && size <= 2) {
			/* 8x-bx: the one-byte register forms with dm == dn are reused by the two-byte immediate forms */
			continue;
		}
		if (rule != size) {
			fprintf (stderr, "row %zu %s: length rule %d, format size %d\n", i, op->name, rule, size);
			abort ();
		}
	}
}

static void unit_tests(void) {
	/* the reset vector of an OM System camera firmware (AM33) */
	check ("fafcfff0", "and 0xf0ff, psw", R_ANAL_OP_TYPE_AND);
	check ("cb", "nop", R_ANAL_OP_TYPE_NOP);
	check ("f8fefc", "add -0x4, sp", R_ANAL_OP_TYPE_ADD);
	check ("fcff8c000000", "calls 0x0000108c", R_ANAL_OP_TYPE_CALL);
	check ("fcde00001098", "mov 0x98100000, a2", R_ANAL_OP_TYPE_MOV);
	check ("8f10", "mov 0x10, d3", R_ANAL_OP_TYPE_MOV);
	check ("f81e08", "mov d3, (0x8, a2)", R_ANAL_OP_TYPE_STORE);
	check ("dd17040000c02c", "call 0x00001417, [d2,d3], 0x2c", R_ANAL_OP_TYPE_CALL);
	check ("fafe00ff", "add -0x100, sp", R_ANAL_OP_TYPE_ADD);
	check ("f2f0", "mov a0, sp", R_ANAL_OP_TYPE_MOV);
	check ("f0f4", "jmp (a0)", R_ANAL_OP_TYPE_RJMP);
	check ("387080", "movhu (0x8070), d0", R_ANAL_OP_TYPE_LOAD);
	check ("037080", "movhu d0, (0x8070)", R_ANAL_OP_TYPE_STORE);
	check ("f0fc", "rets", R_ANAL_OP_TYPE_RET);
	check ("dfc008", "ret [d2,d3], 0x8", R_ANAL_OP_TYPE_RET);
	check ("dec008", "retf [d2,d3], 0x8", R_ANAL_OP_TYPE_RET);
	check ("cf30", "movm [a2,a3], (sp)", R_ANAL_OP_TYPE_RPUSH);
	check ("ce30", "movm (sp), [a2,a3]", R_ANAL_OP_TYPE_POP);
	check ("70", "mov (a0), d0", R_ANAL_OP_TYPE_LOAD);
	check ("60", "mov d0, (a0)", R_ANAL_OP_TYPE_STORE);
	check ("4e1e", "mov d3, (0x1e, sp)", R_ANAL_OP_TYPE_STORE);
	check ("5a1e", "mov (0x1e, sp), d2", R_ANAL_OP_TYPE_LOAD);
	check ("00", "clr d0", R_ANAL_OP_TYPE_MOV);
	check ("1f", "exthu d3", R_ANAL_OP_TYPE_CAST);
	check ("f2d0", "ext d0", R_ANAL_OP_TYPE_CAST);
	check ("a005", "cmp 0x5, d0", R_ANAL_OP_TYPE_CMP);
	check ("c004", "blt 0x00001004", R_ANAL_OP_TYPE_CJMP);
	check ("c802", "beq 0x00001002", R_ANAL_OP_TYPE_CJMP);
	check ("ca3c", "bra 0x0000103c", R_ANAL_OP_TYPE_JMP);
	check ("fac2ebfe", "add -0x115, d2", R_ANAL_OP_TYPE_ADD);
	check ("fac8e40c", "cmp 0xce4, d0", R_ANAL_OP_TYPE_CMP);
	check ("f26c", "div d3, d0", R_ANAL_OP_TYPE_DIV);
	check ("f27c", "divu d3, d0", R_ANAL_OP_TYPE_DIV);
	check ("f24c", "mul d3, d0", R_ANAL_OP_TYPE_MUL);
	check ("f25c", "mulu d3, d0", R_ANAL_OP_TYPE_MUL);
	check ("f2f2", "mov d0, mdr", R_ANAL_OP_TYPE_MOV);
	check ("f2e0", "mov mdr, d0", R_ANAL_OP_TYPE_MOV);
	check ("fe027080000002", "btst 0x2, (0x8070)", R_ANAL_OP_TYPE_ACMP);
	check ("fe007080000080", "bset 0x80, (0x8070)", R_ANAL_OP_TYPE_OR);
	check ("fe017080000080", "bclr 0x80, (0x8070)", R_ANAL_OP_TYPE_AND);
	check ("f8c707", "lsr 0x7, d3", R_ANAL_OP_TYPE_SHR);
	check ("db", "setlb", R_ANAL_OP_TYPE_MOV);
	check ("d9", "lne", R_ANAL_OP_TYPE_UCJMP);
	check ("f0fe", "trap", R_ANAL_OP_TYPE_SWI);
	check ("ff", "break", R_ANAL_OP_TYPE_TRAP);
	/* the AM30/AM33 names win over the udf placeholders when the cpu accepts them */
	check ("f60c", "mulq d3, d0", R_ANAL_OP_TYPE_MUL);
	check ("f9140a", "mulqu 0xa, d0", R_ANAL_OP_TYPE_MUL);
	check ("f90123", "mulq 0x23, d1", R_ANAL_OP_TYPE_MUL);
	check ("f684", "swap d1, d0", R_ANAL_OP_TYPE_MOV);
	check_cpu ("mn10300", "f60c", "udf00 d3, d0", R_ANAL_OP_TYPE_UNK, 0x1000);
	check_cpu ("mn10300", "f9140a", "udfu01 0xa, d0", R_ANAL_OP_TYPE_UNK, 0x1000);
	/* AM33 extended registers, three-operand and pair forms */
	check ("f90800", "mov r0, r0", R_ANAL_OP_TYPE_MOV);
	check ("f9e890", "mov xr9, r0", R_ANAL_OP_TYPE_MOV);
	check ("fb0f0000", "mac r0, r0, r0, r0", R_ANAL_OP_TYPE_MUL);
	check ("f7622c3d", "sub_mov r2, d0, r3, d1", R_ANAL_OP_TYPE_SUB);
	/* AM33-2 floating point */
	check ("f9e040", "fadd fd4, fd0", R_ANAL_OP_TYPE_UNK);
	check ("f9b700", "fmov fpcr, r0", R_ANAL_OP_TYPE_MOV);
	/* fmov (an+), fsN: post-increment on a 4-byte access */
	check_esil ("f92280", "a0,[4],fs0,=,4,a0,+=");
	/* unknown opcodes are 1-byte illegal instructions */
	check_invalid ("f7ff0000");
	check_invalid ("f1ff");
	/* ESIL */
	check_esil ("f8fefc", "0xfffffffc,sp,+=");
	check_esil ("e4", "d1,d0,+=,$z,zf,:=,31,$s,nf,:=,31,$c,cf,:=,31,$o,vf,:=");
	check_esil ("a005", "0x5,d0,==,$z,zf,:=,31,$s,nf,:=,32,$b,cf,:=,31,$o,vf,:=");
	check_esil ("c004", "nf,vf,^,?{,0x1004,pc,=,}");
	check_esil ("f26c", "32,mdr,<<,d0,|,DUP,32,d3,~,SWAP,~%,mdr,=,32,d3,~,SWAP,~/,d0,=,$z,zf,:=,31,$s,nf,:=");
	check_esil ("f2d0", "0x80000000,d0,&,?{,0xffffffff,mdr,=,}{,0,mdr,=,}");
	check_esil ("dd17040000c02c", "0x1007,mdr,=,4,sp,-=,0x1007,sp,=[4],d2,4,sp,-,=[4],d3,8,sp,-,=[4],8,sp,-=,0x2c,sp,-=,0x1417,pc,=");
	check_esil ("dfc008", "0x8,sp,+=,0,sp,+,[4],d3,=,4,sp,+,[4],d2,=,8,sp,+=,sp,[4],pc,=,4,sp,+=");
	check_esil ("f0fc", "sp,[4],pc,=,4,sp,+=");
	check_esil ("cf30", "a2,4,sp,-,=[4],a3,8,sp,-,=[4],8,sp,-=");
	check_esil ("ce30", "4,sp,+,[4],a2,=,8,sp,+=");
	check_esil ("f81e08", "d3,0x8,a2,+,=[4]");
	check_esil ("387080", "0x8070,[2],d0,=");
	check_esil ("1f", "0xffff,d3,&=");
	check_esil ("1b", "16,d3,~,d3,=");
	check_esil ("f60c", "d3,d0,*=,$z,zf,:=,31,$s,nf,:=");
	check_esil ("db", "0x1001,lar,=,0x1001,[4],lir,=");
	check_esil ("d9", "zf,!,?{,lar,pc,=,}");
	length_rule ();
}

static void regs_profile(void) {
	char *p = regs (&session);
	assert (p && strstr (p, "=SP sp") && strstr (p, "gpr a3 .32 28 0") && strstr (p, "gpr sp .32 28 0"));
	assert (strstr (p, "flg zf .1 36.0 0") && strstr (p, "flg vf .1 36.3 0"));
	free (p);
	assert (info (&session, R_ARCH_INFO_MAXOP_SIZE) == 7);
	assert (info (&session, R_ARCH_INFO_MINOP_SIZE) == 1);
}

int main(void) {
	unit_tests ();
	regs_profile ();
	printf ("mn103 unit tests passed\n");
	return 0;
}
