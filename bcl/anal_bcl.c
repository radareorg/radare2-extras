/* radare2 - LGPL - Copyright 2015 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static ut64 bcl_addr = UT64_MAX;
#define BCL_SIZE 128
static bool bcl_data[BCL_SIZE];

static int findpair(ut64 addr, const ut8 *buf, int len, int base) {
	int i, j;
	for (i = 1; i<len; i++) {
		if ((buf[i] & 3) != base) {
			continue;
		}
		if (bcl_addr != UT64_MAX) {
			if (addr < bcl_addr || addr >= bcl_addr + BCL_SIZE) {
				bcl_addr = UT64_MAX;
			}
		}
		if (bcl_addr == UT64_MAX) {
			bcl_addr = addr;
			for (j = 0; j < BCL_SIZE; j++) {
				bcl_data[j] = false;
			}
		} else {
			if (bcl_data[ (addr - bcl_addr) - i]) {
			// XXX fix	continue;
			}
		}
		bcl_data[ (addr - bcl_addr)-i] = true;
		return i;
	}
	return 0;
}

static int bcl_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	int i;
	char cache[256] = {0};
	ut64 dst = 0LL;
	if (op == NULL)
		return 1;
	int base = *buf & 3;
	memset (op, 0, sizeof (RAnalOp));
	r_strbuf_init (&op->esil);
	op->size = 1;
	if (*buf == 0) {
		op->type = R_ANAL_OP_TYPE_NOP;
		return 0;
	}
	switch (base) {
	case 0:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + findpair (addr, buf, len, 3);
		op->fail = addr + 1;
		r_strbuf_setf (&op->esil, "A,++=");
		break;
	case 1:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + findpair(addr, buf, len, 2);
		op->fail = addr + 1;
		r_strbuf_setf (&op->esil, "C,++=");
		break;
	case 2:
		op->type = R_ANAL_OP_TYPE_CMP;
		r_strbuf_setf (&op->esil, "G,++=");
		break;
	case 3:
		op->type = R_ANAL_OP_TYPE_MOV;
		r_strbuf_setf (&op->esil, "T,++=");
		break;
	}
	return op->size;
}

static int set_reg_profile(RAnal *anal) {
	const char *p = \
		"=PC	pc\n"
		"=SP	sp\n"
		"=A0	A\n"
		"=A1	C\n"
		"=A2	G\n"
		"=A3	T\n"
		"gpr	pc	.64	0	0\n"
		"gpr	sp	.64	8	0\n"
		"gpr	A	.8	16	0\n"
		"gpr	C	.8	17	0\n"
		"gpr	G	.8	18	0\n"
		"gpr	T	.8	19	0\n";
	return r_reg_set_profile_string (anal->reg, p);
}

struct r_anal_plugin_t r_anal_plugin_bcl = {
	.name = "bcl",
	.desc = "Base Call DNA Illumina records",
	.license = "BSD",
	.arch = "bcl",
	.bits = 8,
	.esil = true,
	.op = &bcl_op,
	.set_reg_profile = set_reg_profile,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_bcl,
	.version = R2_VERSION
};
#endif
