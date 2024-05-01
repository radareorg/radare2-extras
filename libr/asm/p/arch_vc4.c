/* radare - LGPL - Copyright 2016 - pancake */

#include <r_lib.h>
#include <r_asm.h>
#include <r_arch.h>

#define BUFSZ 8
#include "disas-asm.h"

static int vc4_buffer_read_memory (bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
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

static int symbol_at_address(bfd_vma addr, struct disassemble_info * info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC_NOGLOBALS()
DECLARE_GENERIC_FPRINTF_FUNC_NOGLOBALS()

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
	disasm_obj.disassembler_options = (a->config->bits == 64)? "64": "";
	disasm_obj.buffer = bytes;
	disasm_obj.buffer_vma = op->addr;
	disasm_obj.read_memory_func = &vc4_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = a->config->big_endian;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;

	op->size = print_insn_vc4 ((bfd_vma)op->addr, &disasm_obj);
	if (op->size == -1) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return false;
	}

	char *instr = sb? r_strbuf_drain (sb): NULL;
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

static int info(RArchSession *s, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_MIN_OP_SIZE:
		return 2;
	case R_ARCH_INFO_MAX_OP_SIZE:
		return 6;
	}
	return 2;
}

static char *getregs(RArchSession *as) {
	const char *const p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=GP	gp\n"
		"=SR	sr\n"
		"=LR	lr\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
		"=A4	r4\n"
		"=A5	r5\n"
		"=R0	r0\n"
		"=SN	r0\n"	// Avoid warning but wrong: register holding
						// syscall number changes depending on the
						// instructions (swi r0, swi r1, ...)
		"gpr	r0	.32	0	0\n"
		"gpr	r1	.32	8	0\n"
		"gpr	r2	.32	16	0\n"
		"gpr	r3	.32	24	0\n"
		"gpr	r4	.32	32	0\n"
		"gpr	r5	.32	40	0\n"
		"gpr	r6	.32	48	0\n"
		"gpr	r7	.32	56	0\n"
		"gpr	r8	.32	64	0\n"
		"gpr	r9	.32	72	0\n"
		"gpr	r10	.32	80	0\n"
		"gpr	r11	.32	88	0\n"
		"gpr	r12	.32	96	0\n"
		"gpr	r13	.32	104	0\n"
		"gpr	r14	.32	112	0\n"
		"gpr	r15	.32	120	0\n"
		"gpr	r16	.32	128	0\n"
		"gpr	r17	.32	136	0\n"
		"gpr	r18	.32	144	0\n"
		"gpr	r19	.32	152	0\n"
		"gpr	r20	.32	160	0\n"
		"gpr	r21	.32	168	0\n"
		"gpr	r22	.32	176	0\n"
		"gpr	r23	.32	184	0\n"
		"gpr	gp	.32	192	0\n"
		"gpr	sp	.32	200	0\n"
		"gpr	lr	.32	208	0\n"
		"gpr	r27	.32	216	0\n"
		"gpr	r28	.32	224	0\n"
		"gpr	r29	.32	232	0\n"
		"gpr	sr	.32	240	0\n"
		"gpr	pc	.32	248	0\n"
		;
	return strdup (p);
}

RArchPlugin r_arch_plugin_vc4 = {
	.meta = {
		.name = "vc4",
		.desc = "VideoCore IV",
		.author = "",
		.version = "",
		.license = "GPL3",
		.status = R_PLUGIN_STATUS_OK,
	},
	.arch = "vc4",
	.bits = R_SYS_BITS_PACK1 (32),
	.endian = R_SYS_ENDIAN_LITTLE,
	.info = &info,
	.regs = getregs,
	.decode = &decode
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_vc4,
	.version = R2_VERSION
};
#endif
