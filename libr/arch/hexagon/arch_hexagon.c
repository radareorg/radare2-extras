/* radare - LGPL - Copyright 2015-2023 - condret */

#include <r_arch.h>
#include <r_lib.h>
#include "hexagon.h"
#include "hexagon_insn.h"
#include "hexagon_anal.h"

static bool mal_decode(RArchSession *s, RAnalOp *op, RArchEncodeMask mask) {
	if (op->size < 4 || !op->bytes) {
		return false;
	}
	ut32 data = r_read_le32 (op->bytes);
	HexInsn hi = {0};
	int size = hexagon_disasm_instruction (data, &hi, (ut32) (op->addr & UT32_MAX));
	if (size > 0 && mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = strdup (hi.mnem);
	}
	op->size = size;
	if (size < 1) {
		return false;
	}
	op->vliw = hi.op_count;
	int res = hexagon_anal_instruction (&hi, op);
	if (op->size != res) {
		R_LOG_DEBUG ("shouldnt happen invalid instruction at 0x%08"PFMT64x, op->addr);
	}
	op->size = res;
	return true;
}

static char* regs(RArchSession *as) {
	return strdup (
		"=PC	pc\n"
		"=SP	r29\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
		"=A4	r4\n"
		"=A5	r5\n"
		"=BP	r30\n"
		"=LR	r31\n"
		"=SN	r6\n"
		"=ZF	z\n"
		"=SF	s\n"
		"=OF	ov\n"
		"=CF	cy\n"

		"gpr	r0	.32	0   0\n"
		"gpr	r1	.32	4   0\n"
		"gpr	r2	.32	8   0\n"
		"gpr	r3	.32	12  0\n"
		"gpr	r4	.32	16  0\n"
		"gpr	r5	.32	20  0\n"
		"gpr	r6	.32	24  0\n"
		"gpr	r7	.32	28  0\n"
		"gpr	r8	.32	32  0\n"
		"gpr	r9	.32	36  0\n"
		"gpr	r10	.32	40  0\n"
		"gpr	r11	.32	44  0\n"
		"gpr	r12	.32	48  0\n"
		"gpr	r13	.32	52  0\n"
		"gpr	r14	.32	56  0\n"
		"gpr	r15	.32	60  0\n"
		"gpr	r16	.32	64  0\n"
		"gpr	r17	.32	68  0\n"
		"gpr	r18	.32	72  0\n"
		"gpr	r19	.32	76  0\n"
		"gpr	r20	.32	80  0\n"
		"gpr	r21	.32	84  0\n"
		"gpr	r22	.32	88  0\n"
		"gpr	r23	.32	92  0\n"
		"gpr	r24	.32	96  0\n"
		"gpr	r25	.32	100 0\n"
		"gpr	r26	.32	104 0\n"
		"gpr	r27	.32	108 0\n"
		"gpr	r28	.32	112 0\n"
		"gpr	r29	.32	116 0\n"
		"gpr	r30	.32	120 0\n"
		"gpr	r31	.32	124 0\n"
		"gpr	pc	.32	128 0\n"

		"gpr	psw .32 132 0\n"
		"gpr	np  .1 132.16 0\n"
		"gpr	ep  .1 132.17 0\n"
		"gpr	ae  .1 132.18 0\n"
		"gpr	id  .1 132.19 0\n"
		"flg	cy  .1 132.28 0\n"
		"flg	ov  .1 132.29 0\n"
		"flg	s   .1 132.30 0\n"
		"flg	z   .1 132.31 0\n");
}
RArchPlugin r_arch_plugin_hexagon = {
	.meta = {
		.name = "hexagon",
		.desc = "Qualcomm Hexagon (QDSP6) V6",
		.author = "pancake,condret,xvilka",
		.license = "LGPL3",
	},
	.regs = regs,
	.arch = "hexagon",
	.bits = 32,
	.decode = &mal_decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_hexagon,
	.version = R2_VERSION
};
#endif
