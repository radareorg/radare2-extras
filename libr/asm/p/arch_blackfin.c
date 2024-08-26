/* radare - LGPL - Copyright 2015-2024 - pancake */

#include <r_lib.h>
#include <r_asm.h>
#include <r_arch.h>

#define BUFSZ 8
#include "disas-asm.h"

#include "blackfin/bfin-dis.c"
#include "blackfin/bfin-asm.c"

static int blackfin_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - info->buffer_vma);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if (delta >= BUFSZ) {
		return -1;
	}
	ut8 *bytes = info->buffer;
	int nlen = R_MIN (length, BUFSZ - delta);
	if (nlen > 0) {
		memcpy (myaddr, bytes + delta, nlen);
	}
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC_NOGLOBALS()
DECLARE_GENERIC_FPRINTF_FUNC_NOGLOBALS()


static bool encode(RArchSession *a, RAnalOp *op, RArchEncodeMask mask) {
// static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	ut8 hexbuf[8];
	int oplen = bfin_assemble (op->mnemonic, (uint32_t)(op->addr), hexbuf);
	r_anal_op_set_bytes (op, op->addr, hexbuf, oplen);
	return oplen > 1;
}

static bool decode(RArchSession *a, RAnalOp *op, RArchDecodeMask mask) {
	ut8 bytes[BUFSZ] = {0};
	struct disassemble_info disasm_obj = {0};
	if (op->size < 2) {
		op->mnemonic = strdup ("truncated");
		return false;
	}
	RStrBuf *sb = r_strbuf_new (NULL);
	memcpy (bytes, op->bytes, R_MIN (op->size, BUFSZ));
	/* prepare disassembler */
	disasm_obj.disassembler_options = NULL;
	 // bfin_cpu_t bfin_cpu_type = BFIN_CPU_BF707; // UNKNOWN;
        disasm_obj.buffer = bytes;
        disasm_obj.buffer_vma = op->addr;
        disasm_obj.read_memory_func = &blackfin_buffer_read_memory;
        disasm_obj.symbol_at_address_func = &symbol_at_address;
        disasm_obj.memory_error_func = &memory_error_func;
        disasm_obj.print_address_func = &generic_print_address_func;
        disasm_obj.endian = !a->config->big_endian;
	disasm_obj.fprintf_func = &generic_fprintf_func;
        disasm_obj.stream = sb;

	op->size = print_insn_bfin ((bfd_vma)op->addr, &disasm_obj);
        if (op->size < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return false;
	}

	char *instr = sb? r_strbuf_drain (sb): NULL;
	if (instr) {
		r_str_case (instr, false);
		char *colon = strstr (instr, ";");
		if (colon) {
			*colon = 0;
		}
		const char *arg = strstr (instr, "0x");
		ut64 n = 0;
		if (arg) {
			n = r_num_get (NULL, arg);
		}
		if (r_str_startswith (instr, "invalid") || !strcmp (instr, "illegal")) {
			R_FREE (instr);
			op->type = R_ANAL_OP_TYPE_ILL;
			op->size = 4;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = strdup ("invalid");
			}
			free (instr);
			return false;
		}
		if (!strcmp (instr, "nop") || !strcmp (instr, "mnop")) {
			op->type = R_ANAL_OP_TYPE_NOP;
		} else if (r_str_startswith (instr, "if ")) {
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = n;
			op->fail = op->addr + 2;
		} else if (r_str_startswith (instr, "rts")) {
			op->type = R_ANAL_OP_TYPE_RET;
		} else if (r_str_startswith (instr, "call ")) {
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = n;
			op->fail = op->addr + 2;
		} else if (r_str_startswith (instr, "j")) {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = n;
		} else if (strstr (instr, " = [")) {
			op->type = R_ANAL_OP_TYPE_LOAD;
		} else if (strstr (instr, "] = ")) {
			op->type = R_ANAL_OP_TYPE_STORE;
		} else if (strstr (instr, ">>>")) {
			op->type = R_ANAL_OP_TYPE_ROR;
			op->val = n;
		} else if (strstr (instr, ">>=")) {
			op->type = R_ANAL_OP_TYPE_SHR;
			op->val = n;
		} else if (strstr (instr, "<<<")) {
			op->type = R_ANAL_OP_TYPE_ROL;
			op->val = n;
		} else if (strstr (instr, "<<=")) {
			op->type = R_ANAL_OP_TYPE_SHL;
			op->val = n;
		} else if (strstr (instr, "=")) {
			op->type = R_ANAL_OP_TYPE_MOV;
			op->val = n;
		}
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		if (op->size > 0) {
			op->mnemonic = instr? instr: strdup ("");
			r_str_replace_char (op->mnemonic, '\t', ' ');
		} else {
			free (instr);
			op->mnemonic = strdup ("(data)");
		}
	} else {
		free (instr);
	}
	return true;
}

#if 0
  REG_R0, REG_R1, REG_R2, REG_R3, REG_R4, REG_R5, REG_R6, REG_R7,
  REG_P0, REG_P1, REG_P2, REG_P3, REG_P4, REG_P5, REG_SP, REG_FP,
  REG_I0, REG_I1, REG_I2, REG_I3, REG_M0, REG_M1, REG_M2, REG_M3,
  REG_B0, REG_B1, REG_B2, REG_B3, REG_L0, REG_L1, REG_L2, REG_L3,
  REG_A0x, REG_A0w, REG_A1x, REG_A1w, REG_LASTREG, REG_LASTREG, REG_ASTAT, REG_RETS,
  REG_LASTREG, REG_LASTREG, REG_LASTREG, REG_LASTREG, REG_LASTREG, REG_LASTREG, REG_LASTREG, REG_LASTREG,
  REG_LC0, REG_LT0, REG_LB0, REG_LC1, REG_LT1, REG_LB1, REG_CYCLES, REG_CYCLES2,
  REG_USP, REG_SEQSTAT, REG_SYSCFG, REG_RETI, REG_RETX, REG_RETN, REG_RETE, REG_EMUDAT,
  REG_LASTREG,
#endif
static char *getregs(RArchSession *as) {
	const char *const p =
		"=PC    pc\n"
		"=SP    sp\n"
		"=BP    fp\n"
		"=A0    r0\n"
		"=A1    r1\n"
		"=A2    r2\n"
		"=A3    r3\n"
		"=SN    r0\n"
		"=R0    r0\n"
		"=R1    r1\n"
		"gpr	r0	.32	0	0\n"
		"gpr	r1	.32	8	0\n"
		"gpr	r2	.32	16	0\n"
		"gpr	r3	.32	24	0\n"
		"gpr	r4	.32	32	0\n"
		"gpr	r5	.32	40	0\n"
		"gpr	r6	.32	48	0\n"
		"gpr	r7	.32	56	0\n"
		"gpr	p0	.32	64	0\n"
		"gpr	p1	.32	72	0\n"
		"gpr	p2 	.32	80	0\n"
		"gpr	p3 	.32	88	0\n"
		"gpr	p4 	.32	96	0\n"
		"gpr	p5 	.32	104	0\n"
		"gpr	sp 	.32	112	0\n"
		"gpr	fp 	.32	120	0\n"
		"gpr	i0	.32	128	0\n"
		"gpr	i1	.32	136	0\n"
		"gpr	i2	.32	144	0\n"
		"gpr	i3	.32	152	0\n"
		"gpr	m0 	.32	160	0\n"
		"gpr	m1 	.32	168	0\n"
		"gpr	m2 	.32	176	0\n"
		"gpr	m3	.32	184	0\n"
		"gpr	b0	.32	192	0\n"
		"gpr	b1 	.32	200	0\n"
		"gpr	b2	.32	208	0\n"
		"gpr	b3	.32	216	0\n"
		"gpr	l0	.32	224	0\n"
		"gpr	l1	.32	232	0\n"
		"gpr	l2	.32	240	0\n"
		"gpr	l3	.32	248	0\n"
		"gpr	pc	.32	256	0\n";
	return strdup (p);
}

static int info(RArchSession *s, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_MIN_OP_SIZE:
		return 2;
	case R_ARCH_INFO_MAX_OP_SIZE:
		return 4;
	}
	// i think data align is 4
	return 2;
}

static RList *preludes(RArchSession *as) {
	RList *l = r_list_newf (free);
	// must be aligned to 4 i think
	r_list_append (l, r_str_newf ("00 e8"));
	return l;
}

RArchPlugin r_arch_plugin_blackfin = {
	.meta = {
		.name = "blackfin",
		.desc = "BlackFIN architecture plugin",
		.author = "pancake",
		.version = "0.2",
		.license = "GPL",
		.status = R_PLUGIN_STATUS_OK,
	},
	.arch = "blackfin",
	.bits = R_SYS_BITS_PACK1 (32),
	.endian = R_SYS_ENDIAN_LITTLE,
	.info = &info,
	.regs = getregs,
	.preludes = preludes,
	.encode = &encode,
	.decode = &decode
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_blackfin,
	.version = R2_VERSION
};
#endif
