/* radare2 - LGPL-3.0-only - Copyright 2026 - pancake */
#include <r_anal.h>
#define R2_PLUGIN_INCORE 1
#include "../arch_md32.c"
#include <assert.h>

static RArchConfig config = { .bits = 32, .endian = R_SYS_ENDIAN_BIG };
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

static void check(ut32 word, int size, const char *text, int type) {
	ut8 bytes[4];
	if (size == 2) {
		r_write_be16 (bytes, word);
	} else {
		r_write_be32 (bytes, word);
	}
	RAnalOp op;
	assert (run (&op, bytes, size, 0x1000, "md32", R_ARCH_OP_MASK_ALL));
	if (strcmp (op.mnemonic, text) || op.type != (ut32)type || op.size != size) {
		fprintf (stderr, "%08x: got %s (%d, %d), expected %s (%d, %d)\n",
			word, op.mnemonic, op.type, op.size, text, type, size);
		abort ();
	}
	r_anal_op_fini (&op);
}

static void unit_tests(void) {
	check (0x0400e321, 4, "add r1, r2, r3", R_ANAL_OP_TYPE_ADD);
	check (0x08ffff21, 4, "add r1, r2, -0x1", R_ANAL_OP_TYPE_ADD);
	check (0x01fffff1, 4, "mv r1, -0x1", R_ANAL_OP_TYPE_MOV);
	check (0x0f123401, 4, "sethi r1, 0x1234", R_ANAL_OP_TYPE_MOV);
	check (0x060fff21, 4, "lbu r2, -0x1(r1)", R_ANAL_OP_TYPE_LOAD);
	check (0x06c00821, 4, "lw r2, (r1+=0x8)", R_ANAL_OP_TYPE_LOAD);
	check (0x067ffc2e, 4, "sw r2, -0x4(r14)", R_ANAL_OP_TYPE_STORE);
	check (0x04154061, 4, "mv r1, le0", R_ANAL_OP_TYPE_MOV);
	check (0x04182025, 4, "mv ls0, r2", R_ANAL_OP_TYPE_MOV);
	check (0x1e1fffff, 4, "j 0x00000ffe", R_ANAL_OP_TYPE_JMP);
	check (0x1f000020, 4, "jal 0x00001040", R_ANAL_OP_TYPE_CALL);
	check (0x1f800002, 4, "jal r2", R_ANAL_OP_TYPE_RCALL);
	check (0xa03f, 2, "j16 r15", R_ANAL_OP_TYPE_RET);
	check (0xa02f, 2, "j16.d2 r15", R_ANAL_OP_TYPE_RET);
	check (0xa180, 2, "j16 0x00001000", R_ANAL_OP_TYPE_JMP);
	check (0xa1ff, 2, "j16 0x00000ffe", R_ANAL_OP_TYPE_JMP);
	check (0x9811, 2, "mv16 r1, 0x1", R_ANAL_OP_TYPE_MOV);
	check (0x9ff1, 2, "mv16 r1, -0x1", R_ANAL_OP_TYPE_MOV);
	check (0x81ff, 2, "and16 r8, r8, 0xffff", R_ANAL_OP_TYPE_AND);
	check (0xa401, 2, "lw16 r1, -0x80(r14)", R_ANAL_OP_TYPE_LOAD);
	check (0xb781, 2, "sw16 r1, (r1+=-0x4)", R_ANAL_OP_TYPE_STORE);
	check (0xbc11, 2, "beq16 0x0, r1, 0x00001002", R_ANAL_OP_TYPE_CJMP);
	check (0x4600203f, 4, "xor16 r0, r0 | j16 r15", R_ANAL_OP_TYPE_RET);
	check (0x40002000, 4, "nop16 | nop16.l", R_ANAL_OP_TYPE_UNK);
	check (0x20002000, 4, "add r0, r0, r0, 0x1", R_ANAL_OP_TYPE_ADD);
	check (0x05000000, 4, "nop", R_ANAL_OP_TYPE_NOP);

	RAnalOp op;
	const ut8 bytes[] = { 0x14, 0x00, 0x02, 0x21, 0x98, 0x11, 0x98, 0x22 };
	assert (run (&op, bytes, sizeof (bytes), 0x1000, "md32", R_ARCH_OP_MASK_ALL));
	assert (op.type == R_ANAL_OP_TYPE_CJMP && op.delay == 1 && op.jump == 0x1004);
	assert (!*r_strbuf_get (&op.esil));
	assert (op.fail == 0x1006);
	r_anal_op_fini (&op);
	// A delayed conditional branch with no lookahead has no known fallthrough.
	assert (run (&op, bytes, 4, 0x1000, "md32", R_ARCH_OP_MASK_ALL));
	assert (op.fail == UT64_MAX && op.delay == 1);
	r_anal_op_fini (&op);
	const ut8 wrap[] = { 0x1f, 0x00, 0x00, 0x02 };
	assert (run (&op, wrap, 4, 0xfffffffe, "md32", R_ARCH_OP_MASK_ALL));
	assert (op.jump == 2 && op.fail == 2);
	r_anal_op_fini (&op);

	const ut8 high[] = { 0x0f, 0x12, 0x34, 0x01 };
	assert (run (&op, high, 4, 0, "md32", R_ARCH_OP_MASK_ALL));
	assert (op.val == 0x12340000);
	assert (RVecRArchValue_at (&op.srcs, 0)->imm == 0x12340000);
	r_anal_op_fini (&op);

	const ut8 ret[] = { 0xde, 0xf9 };
	assert (run (&op, ret, 2, 0x1000, "usip", R_ARCH_OP_MASK_ALL));
	assert (op.type == R_ANAL_OP_TYPE_RET && op.eob);
	r_anal_op_fini (&op);
	const ut8 call[] = { 0x00, 0x0e, 0x78, 0xaa };
	assert (run (&op, call, 4, 0x1ca7292c, "usip", R_ARCH_OP_MASK_ALL));
	assert (op.type == R_ANAL_OP_TYPE_CALL && op.jump == 0x1ca731d6);
	r_anal_op_fini (&op);

	// Every truncated prefix must fail without reading beyond its buffer.
	unsigned h, len;
	for (h = 0; h <= 0xffff; h++) {
		ut8 bytes[4];
		r_write_be32 (bytes, h << 16);
		for (len = 0; len <= 3; len++) {
			ut8 *exact = malloc (len? len: 1);
			memcpy (exact, bytes, len);
			const bool ok = run (&op, exact, len, 0x1000, "md32", R_ARCH_OP_MASK_ALL);
			assert (!ok || op.size <= (int)len);
			assert (!ok || (op.size == 2 && op.mnemonic));
			r_anal_op_fini (&op);
			free (exact);
		}
	}
	// Stateless decoding must give identical output regardless of history.
	for (h = 0; h <= 0xffff; h++) {
		ut8 bytes[4];
		r_write_be32 (bytes, (h << 16) | 0xa03f);
		const bool ok = run (&op, bytes, 4, 0x1000, "md32", R_ARCH_OP_MASK_ALL);
		assert (op.size == 2 || op.size == 4);
		if (ok) {
			RAnalOp basic;
			assert (run (&basic, bytes, 4, 0x1000, "md32", R_ARCH_OP_MASK_BASIC));
			assert (!basic.mnemonic && basic.size == op.size && basic.type == op.type);
			assert (basic.jump == op.jump && basic.delay == op.delay);
			r_anal_op_fini (&basic);
		}
		r_anal_op_fini (&op);
	}
	puts ("MD32 unit, truncation, and exhaustive halfword checks passed");
}

static int stream(const char *cpu) {
	char line[256];
	while (fgets (line, sizeof (line), stdin)) {
		unsigned word, len;
		ut64 addr;
		if (sscanf (line, "%x %u %"SCNx64, &word, &len, &addr) != 3 || len > 4) {
			return 1;
		}
		ut8 bytes[4];
		r_write_be32 (bytes, word);
		RAnalOp op;
		bool ok = run (&op, bytes, len, addr, cpu, R_ARCH_OP_MASK_ALL);
		printf ("%u\t%d\t%d\t%"PFMT64x"\t%"PFMT64x"\t%d\t%s\t%s\n", ok,
			op.size, op.type, op.jump, op.fail, op.delay, op.mnemonic? op.mnemonic: "",
			r_strbuf_get (&op.esil));
		r_anal_op_fini (&op);
	}
	return 0;
}

int main(int argc, char **argv) {
	if (argc > 1 && !strcmp (argv[1], "--stream")) {
		return stream (argc > 2? argv[2]: "md32");
	}
	unit_tests ();
	return 0;
}
