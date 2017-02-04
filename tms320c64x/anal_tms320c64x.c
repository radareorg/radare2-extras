/* radare2 - LGPL - Copyright 2017 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone/capstone.h>
#include <capstone/tms320c64x.h>

static int analop(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	int n, ret, opsize = -1;
	static csh hndl = 0;
	static csh *handle = &hndl;
	static int omode = -1;
	static int obits = 32;
	cs_insn* insn;
	int mode = CS_MODE_BIG_ENDIAN;

	if (mode != omode || anal->bits != obits) {
		cs_close (&hndl);
		hndl = 0;
		omode = mode;
		obits = anal->bits;
	}
// XXX no arch->cpu ?!?! CS_MODE_MICRO, N64
	op->delay = 0;
	op->type = R_ANAL_OP_TYPE_ILL;
	if (len<4) {
		return -1;
	}
	op->size = 4;
	if (hndl == 0) {
		ret = cs_open (CS_ARCH_TMS320C64X, mode, &hndl);
		if (ret != CS_ERR_OK) {
			goto fin;
		}
		cs_option (hndl, CS_OPT_DETAIL, CS_OPT_ON);
	}
	n = cs_disasm (hndl, (ut8*)buf, len, addr, 1, &insn);
	if (n < 1 || insn->size < 1) {
		goto beach;
	}
	op->type = R_ANAL_OP_TYPE_NULL;
	op->delay = 0;
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->id = insn->id;
	opsize = op->size = insn->size;
	switch (insn->id) {
	case TMS320C64X_INS_ABS:
	case TMS320C64X_INS_ABS2:
	case TMS320C64X_INS_ADD:
	case TMS320C64X_INS_ADD2:
	case TMS320C64X_INS_ADD4:
	case TMS320C64X_INS_ADDAB:
	case TMS320C64X_INS_ADDAD:
	case TMS320C64X_INS_ADDAH:
	case TMS320C64X_INS_ADDAW:
	case TMS320C64X_INS_ADDK:
	case TMS320C64X_INS_ADDKPC:
	case TMS320C64X_INS_ADDU:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case TMS320C64X_INS_SUB:
	case TMS320C64X_INS_SUB2:
	case TMS320C64X_INS_SUB4:
	case TMS320C64X_INS_SUBAB:
	case TMS320C64X_INS_SUBABS4:
	case TMS320C64X_INS_SUBAH:
	case TMS320C64X_INS_SUBAW:
	case TMS320C64X_INS_SUBC:
	case TMS320C64X_INS_SUBU:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case TMS320C64X_INS_STB:
	case TMS320C64X_INS_STDW:
	case TMS320C64X_INS_STH:
	case TMS320C64X_INS_STNDW:
	case TMS320C64X_INS_STNW:
	case TMS320C64X_INS_STW:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case TMS320C64X_INS_AND:
	case TMS320C64X_INS_ANDN:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case TMS320C64X_INS_NOT:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case TMS320C64X_INS_NEG:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case TMS320C64X_INS_MV:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case TMS320C64X_INS_AVG2:
	case TMS320C64X_INS_AVGU4:
		break;
	case TMS320C64X_INS_B:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = insn->detail->tms320c64x.operands[0].imm;
		break;
#if 0
	TMS320C64X_INS_BDEC,
	TMS320C64X_INS_BITC4,
	TMS320C64X_INS_BNOP,
	TMS320C64X_INS_BPOS,
		op->type = R_ANAL_OP_TYPE_ILL;
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
#endif
	case TMS320C64X_INS_CMPEQ:
	case TMS320C64X_INS_CMPEQ2:
	case TMS320C64X_INS_CMPEQ4:
	case TMS320C64X_INS_CMPGT:
	case TMS320C64X_INS_CMPGT2:
	case TMS320C64X_INS_CMPGTU4:
	case TMS320C64X_INS_CMPLT:
	case TMS320C64X_INS_CMPLTU:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case TMS320C64X_INS_LDB:
	case TMS320C64X_INS_LDBU:
	case TMS320C64X_INS_LDDW:
	case TMS320C64X_INS_LDH:
	case TMS320C64X_INS_LDHU:
	case TMS320C64X_INS_LDNDW:
	case TMS320C64X_INS_LDNW:
	case TMS320C64X_INS_LDW:
	case TMS320C64X_INS_LMBD:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	}
	beach:
	if (anal->decode) {
#if 0
// TODO: esil
#endif
	}
	cs_free (insn, n);
	//cs_close (&handle);
	fin:
	return opsize;
}

static char *get_reg_profile(RAnal *anal) {
	// XXX : 64bit profile
	const char *p =
		"=PC    pc\n"
		"=SP    sp\n"
		"=A0    a0\n"
		"=A1    a1\n"
		"=A2    a2\n"
		"=A3    a3\n"
		"=R0    v0\n"
		"=R1    v1\n"
		"gpr	zero	.32	0	0\n"
		"gpr	at	.32	4	0\n"
		"gpr	v0	.32	8	0\n"
		"gpr	v1	.32	12	0\n"
		"gpr	a0	.32	16	0\n"
		"gpr	a1	.32	20	0\n"
		"gpr	a2	.32	24	0\n"
		"gpr	a3	.32	28	0\n"
		"gpr	t0	.32	32	0\n"
		"gpr	t1	.32	36	0\n"
		"gpr	t2 	.32	40	0\n"
		"gpr	t3 	.32	44	0\n"
		"gpr	t4 	.32	48	0\n"
		"gpr	t5 	.32	52	0\n"
		"gpr	t6 	.32	56	0\n"
		"gpr	t7 	.32	60	0\n"
		"gpr	s0	.32	64	0\n"
		"gpr	s1	.32	68	0\n"
		"gpr	s2	.32	72	0\n"
		"gpr	s3	.32	76	0\n"
		"gpr	s4 	.32	80	0\n"
		"gpr	s5 	.32	84	0\n"
		"gpr	s6 	.32	88	0\n"
		"gpr	s7 	.32	92	0\n"
		"gpr	t8 	.32	96	0\n"
		"gpr	t9 	.32	100	0\n"
		"gpr	k0 	.32	104	0\n"
		"gpr	k1 	.32	108	0\n"
		"gpr	gp 	.32	112	0\n"
		"gpr	sp	.32	116	0\n"
		"gpr	fp	.32	120	0\n"
		"gpr	ra	.32	124	0\n"
		"gpr	pc	.32	128	0\n"
		"gpr	hi	.64	132	0\n"
		"gpr	lo	.64	140	0\n"
		"gpr	t	.32	148	0\n";
	return strdup (p);
}

static int archinfo(RAnal *anal, int q) {
	return 4;
}

RAnalPlugin r_anal_plugin_tms320c64x_cs = {
	.name = "tms320c64x",
	.desc = "Capstone TMS320 C64X analyzer",
	.license = "BSD",
	.esil = true,
	.arch = "tms320c64x",
	.get_reg_profile = get_reg_profile,
	.archinfo = archinfo,
	.bits = 64,
	.op = &analop,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_tms320c64x_cs,
	.version = R2_VERSION
};
#endif
