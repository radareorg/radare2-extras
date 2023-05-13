/* radare2-au - MIT - Copyright 2018 - pancake */

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int _au_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	if (len < 4) {
		return -1;
	}
	op->size = 4;
	op->cycles = 1;
	switch (data[0]) {
	case AUCPU_OP_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case AUCPU_OP_PLAY:
		op->type = R_ANAL_OP_TYPE_SWI;
		r_strbuf_setf (&op->esil, "#!au.@ r0!r1");
		op->size = 2;
		break;
	case AUCPU_OP_PLAYREG:
		op->size = 2;
		op->type = R_ANAL_OP_TYPE_SWI;
		{
			int r0 = data[1] & 0xf;
			int r1 = (data[1] & 0xf0) >> 4;
			r_strbuf_setf (&op->esil, "#!au.@ r%d!r%d", r0, r1);
		}
		break;
	case AUCPU_OP_TRAP:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case AUCPU_OP_MOVREG:
		op->type = R_ANAL_OP_TYPE_MOV;
		{
			int r0 = data[1] & 0xf;
			int r1 = (data[1] & 0xf0) >> 4;
			r_strbuf_setf (&op->esil, "r%d,r%d,=", r0, r1);
		}
		break;
	case AUCPU_OP_MOV:
		op->type = R_ANAL_OP_TYPE_MOV;
		{
			int v = (data[2] << 8) | data[3];
			int r = data[1];
			r_strbuf_setf (&op->esil, "%d,r%d,=", v, r);
		}
		break;
	case AUCPU_OP_WAVE:
		op->type = R_ANAL_OP_TYPE_STORE;
		aucpu_esil_wave (op, data);
		break;
	case AUCPU_OP_WAIT:
		op->type = R_ANAL_OP_TYPE_NOP;
		{
			int v = (data[2] << 8) | data[3];
			int r = data[1];
			op->cycles = v;
			r_strbuf_setf (&op->esil, "#!!sleep %d", v);
		}
		break;
	case AUCPU_OP_JMP:
		{
			int r0 = data[1] & 0xf;
			int r1 = (data[1] & 0xf0);
			if (r1) {
				int v = (data[2] << 8) | data[3];
				if (r1 == 0xf0) {
					r_strbuf_setf (&op->esil, "%d,pc,-=", r0);
				} else {
					r_strbuf_setf (&op->esil, "%d,pc,+,4,pc,=", r0);
				}
				op->size = 4;
			} else {
				r_strbuf_setf (&op->esil, "r%d,pc,+=", r0);
				op->size = 2;
			}
		}
		break;
	defaultr:
		r_strbuf_setf (&op->esil, "#!?E hello world");
		break;
	}
	return op->size;
}

static int set_reg_profile(RAnal *anal) {
	char *p =
		"=PC	pc\n"
		"=BP	sp\n"
		"=SP	sp\n"
		"gpr	r0	.32	0	0\n"
		"gpr	r1	.32	4	0\n"
		"gpr	r2	.32	8	0\n"
		"gpr	r3	.32	12	0\n"
		"gpr	r4	.32	16	0\n"
		"gpr	r5	.32	20	0\n"
		"gpr	r6	.32	24	0\n"
		"gpr	r7	.32	28	0\n"
		"gpr	r8	.32	32	0\n"
		"gpr	r9	.32	36	0\n"
		"gpr	r10	.32	40	0\n"
		"gpr	r11	.32	44	0\n"
		"gpr	r12	.32	48	0\n"
		"gpr	sp	.32	52	0\n"
		"gpr	bp	.32	56	0\n"
		"gpr	pc	.32	60	0\n"

		"gpr	flags	.8	.192	0\n"
		"gpr	C	.1	.192	0\n"
		"gpr	Z	.1	.193	0\n"
		"gpr	I	.1	.194	0\n"
		"gpr	D	.1	.195	0\n";
	return r_reg_set_profile_string (anal->reg, p);
}

RAnalPlugin r_anal_plugin_au = {
	.name = "au",
	.desc = "virtual audio chip analysis",
	.license = "MIT",
	.arch = "au",
	.bits = 16 | 32,
	.op = &_au_op,
	.set_reg_profile = &set_reg_profile,
	.esil = true,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_au,
	.version = R2_VERSION
};
#endif

