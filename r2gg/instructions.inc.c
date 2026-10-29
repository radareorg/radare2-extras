/* radare2 - LGPL - Copyright 2026 - pancake */

#define GG_INSTRUCTION_CACHE_SIZE 1024

typedef struct {
	ut64 key;
	char *expression;
	ut8 size;
	ut8 cycles;
	ut8 failcycles;
} GameGearInstruction;

static bool gamegear_instruction_decode(RCore *core, GameGearInstruction *instruction, ut16 pc, const ut8 bytes[4]) {
	ut64 key = ((ut64)1 << 56) | ((ut64)bytes[3] << 40) | ((ut64)bytes[2] << 32) | ((ut64)bytes[1] << 24) | ((ut64)bytes[0] << 16) | pc;
	if (instruction->key == key) {
		return true;
	}
	RAnalOp op;
	r_anal_op_init (&op);
	r_anal_op_set_bytes (&op, pc, bytes, 4);
	if (!r_arch_session_decode (core->anal->arch->session, &op, R_ARCH_OP_MASK_ESIL)) {
		r_anal_op_fini (&op);
		return false;
	}
	char *expression = r_strbuf_drain_nofree (&op.esil);
	if (!expression) {
		r_anal_op_fini (&op);
		return false;
	}
	free (instruction->expression);
	instruction->expression = expression;
	instruction->size = op.size;
	instruction->cycles = op.cycles;
	instruction->failcycles = op.failcycles;
	instruction->key = key;
	r_anal_op_fini (&op);
	return true;
}

static void gamegear_instructions_free(GameGearInstruction *instructions) {
	int i;
	for (i = 0; i < GG_INSTRUCTION_CACHE_SIZE; i++) {
		free (instructions[i].expression);
	}
	free (instructions);
}
