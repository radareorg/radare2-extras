/* radare - LGPL - Copyright 2015-2023 - pancake */

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
        disasm_obj.disassembler_options=(a->config->bits == 64)? "64": "";
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

static char *getregs(RArchSession *as) {
	const char *const p =
		"=PC    pc\n"
		"=SP    r30\n"
		"=BP    r28\n"
#if R2_590
		"=RA    r28\n"
		"=GP    r29\n"
#endif
		"=A0    r15\n"
		"=A1    r16\n"
		"=A2    r17\n"
		"=A3    r18\n"
		"=SN    r15\n"
		"=R0    r0\n"
		"=R1    r1\n"
		"gpr	r0	.64	0	0\n"
		"gpr	r1	.64	8	0\n"
		"gpr	r2	.64	16	0\n"
		"gpr	r3	.64	24	0\n"
		"gpr	r4	.64	32	0\n"
		"gpr	r5	.64	40	0\n"
		"gpr	r6	.64	48	0\n"
		"gpr	r7	.64	56	0\n"
		"gpr	r8	.64	64	0\n"
		"gpr	r9	.64	72	0\n"
		"gpr	r10 	.64	80	0\n"
		"gpr	r11 	.64	88	0\n"
		"gpr	r12 	.64	96	0\n"
		"gpr	r13 	.64	104	0\n"
		"gpr	r14 	.64	112	0\n"
		"gpr	r15 	.64	120	0\n"
		"gpr	r16	.64	128	0\n"
		"gpr	r17	.64	136	0\n"
		"gpr	r18	.64	144	0\n"
		"gpr	r19	.64	152	0\n"
		"gpr	r20 	.64	160	0\n"
		"gpr	r21 	.64	168	0\n"
		"gpr	r22 	.64	176	0\n"
		"gpr	r23	.64	184	0\n"
		"gpr	r24	.64	192	0\n"
		"gpr	r25 	.64	200	0\n"
		"gpr	r26	.64	208	0\n"
		"gpr	r27	.64	216	0\n"
		"gpr	r28	.64	224	0\n" // at
		"gpr	r29	.64	232	0\n" // gp
		"gpr	r30	.64	240	0\n" // sp
		"gpr	r31	.64	?0	0\n" // zero
		"gpr	pc	.64	256	0\n"
		"gpr	lr0	.64	264	0\n"
		"gpr	lr1	.64	272	0\n"
		"gpr	fpcr	.64	280	0\n"; // fpu control register
		// TODO: missing F0-F31 floating point registers!
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
	.name = "blackfin",
	.arch = "blackfin",
	.license = "GPL",
	.bits = R_SYS_BITS_PACK1 (32),
	.endian = R_SYS_ENDIAN_LITTLE,
	.info = &info,
	.desc = "BlackFIN architecture plugin",
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
