/* radare2-au - MIT - Copyright 2018 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include "cpu.h"

static int assemble(RAsm *a, RAsmOp *op, const char *str) {
	char *arg = strdup (str);
	r_str_replace_char (arg, ',', ' ');
	RList *args = r_str_split_list (arg, " ", -1);
	const char *mnemonic = r_list_get_n (args, 0);
	ut8 *buf = r_asm_op_get_buf (op);
	op->size = -1;
	if (!strcmp (mnemonic, "nop")) {
		buf[0] = AUCPU_OP_NOP;
		op->size = 4;
	} else if (!strcmp (mnemonic, "mov")) {
		const char *arg0 = r_list_get_n (args, 1);
		buf[0] = AUCPU_OP_MOV;
		op->size = 4;
		if (arg0 && *arg0 == 'r') {
			buf[1] = atoi (arg0 + 1);
			const char *arg1 = r_list_get_n (args, 2);
			if (arg1) {
				if (*arg1 == 'r') {
					buf[0] = AUCPU_OP_MOVREG;
					buf[1] |= atoi (arg0 + 1);
					op->size = 2;
				} else {
					ut16 v = r_num_math (NULL, arg1);
					buf[2] = (v >> 8) & 0xff;
					buf[3] = (v & 0xff);
				}
			}
		}
	} else if (!strcmp (mnemonic, "trap")) {
		op->size = 2;
		buf[0] = AUCPU_OP_TRAP;
	} else if (!strcmp (mnemonic, "wave")) {
		op->size = 4;
		// RETHINK OP, r0, r1 must be 2nd arg
		// wsin r0, r1, r2
	} else if (!strcmp (mnemonic, "play")) {
		buf[0] = AUCPU_OP_PLAY;
		op->size = 2;
		const char *arg0 = r_list_get_n (args, 1);
		if (arg0 && *arg0 == 'r') {
			const char *arg1 = r_list_get_n (args, 2);
			if (arg1 && *arg1 == 'r') {
				ut16 v = r_num_math (NULL, arg1);
				buf[0] = AUCPU_OP_PLAYREG;
				buf[1] = atoi (arg0 + 1);
				buf[1] |= atoi (arg1 + 1) << 4;
				op->size = 2;
			}
		}
	}
	eprintf ("MNEMO %s\n", mnemonic);
	r_list_free (args);
	return op->size;
}

static const char *waveType(const ut8 t) {
	const char *types[] = {
		"sin", "cos", "saw", "rsaw", "pulse",
		"noise", "triangle", "silence", "inc", "dec",
		NULL
	};
	int i = 0;
	for (i=0;types[i] && i<t;i++) {

	}
	return types[i];
}

static void invalid (RAsmOp *op, const ut8 *buf) {
	st16 *dword = (st16*)buf;
	r_asm_op_set_asm (op, sdb_fmt (".short %d", *dword));
	op->size = 2;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	if (len < 4) {
		return -1;
	}
	op->size = 4;
	switch (buf[0]) {
	case AUCPU_OP_NOP:
		r_asm_op_set_asm (op, "nop");
		break;
	case AUCPU_OP_MOVREG:
		{
			int r0 = buf[1] & 0xf;
			int r1 = (buf[1] & 0xf0);
			r_asm_op_set_asm (op, sdb_fmt ("mov r%d, r%d", r0, r1));
		}
		break;
	case AUCPU_OP_MOV:
		{
			int r = buf[1];
			int v = (buf[2] << 8) | buf[3];
			r_asm_op_set_asm (op, sdb_fmt ("mov r%d, %d", r, v));
		}
		break;
	case AUCPU_OP_WAVE:
		{
			int t = buf[1];
			int freq = ((buf[2]<< 8) | buf[3]) << 2;
			const char *type = waveType(buf[1]);
			if (type) {
				r_asm_op_set_asm (op, sdb_fmt ("wave %s, %d", type, freq));
			} else {
				invalid (op, buf);
			}
		}
		break;
	case AUCPU_OP_WAIT:
		{
			int r0 = buf[1] & 0xf;
			int r1 = (buf[1] & 0xf0);
			if (r1) {
				int v = (buf[2] << 8) | buf[3];
				r_asm_op_set_asm (op, sdb_fmt ("wait %d", v));
				op->size = 4;
			} else {
				r_asm_op_set_asm (op, sdb_fmt ("wait r%d", r0));
				op->size = 2;
			}
		}
		break;
	case AUCPU_OP_JMP:
		{
			int r0 = buf[1] & 0xf;
			int r1 = (buf[1] & 0xf0);
			if (r1) {
				int v = (buf[2] << 8) | buf[3];
				if (r1 == 0xf0) {
					v = -v;
				}
				ut64 addr = a->pc + v + 4;
				r_asm_op_set_asm (op, sdb_fmt ("jmp 0x%08"PFMT64x, addr));
				op->size = 4;
			} else {
				r_asm_op_set_asm (op, sdb_fmt ("jmp r%d", r0));
				op->size = 2;
			}
		}
		break;
	case AUCPU_OP_TRAP:
		r_asm_op_set_asm (op, "trap");
		op->size = 2;
		break;
	case AUCPU_OP_PLAY: // DEPRECATE?
		r_asm_op_set_asm (op, "play");
		op->size = 2;
		break;
	case AUCPU_OP_PLAYREG:
		{
			int r0 = buf[1] & 0xf;
			int r1 = (buf[1] & 0xf0) >> 4;
			r_asm_op_set_asm (op, sdb_fmt ("play r%d, r%d", r0, r1));
		}
		break;
	default:
		invalid (op, buf);
		break;
	}
	// unaligned check?
	return op->size;
}

RAsmPlugin r_asm_plugin_au = {
	.name = "au",
	.desc = "virtual audio chip",
	.arch = "au",
	.bits = 8|16|32,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.license = "MIT",
	.assemble = &assemble,
	.disassemble = &disassemble,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_au,
	.version = R2_VERSION
};
#endif

