/* radare2 - LGPL - Copyright 2021 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "disas-asm.h"
#include "mybfd.h"
int m32c_assemble(const char *str, ut64 pc, ut8 *out);

static unsigned long Offset = 0;
static RStrBuf *buf_global = NULL;
static unsigned char bytes[8];
static char *pre_cpu = NULL;
static char *pre_features = NULL;

static int m32c_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, struct disassemble_info *info) {
	int delta = (memaddr - Offset);
	if (delta < 0) {
		return -1;      // disable backward reads
	}
	if ((delta + length) > sizeof (bytes)) {
		return -1;
	}
	memcpy (myaddr, bytes + delta, length);
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info * info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC()
DECLARE_GENERIC_FPRINTF_FUNC()

static int disassemble(RAnal *a, RAnalOp *op, const ut8 *buf, int len) {
	struct disassemble_info disasm_obj = {0};
	if (len < sizeof (bytes)) {
		return -1;
	}
	buf_global = r_strbuf_new ("");
	memcpy (bytes, buf, R_MIN (sizeof (bytes), len));
	Offset = op->addr;
	memcpy (bytes, buf, R_MIN (len, sizeof (bytes)));

	/* prepare disassembler */
	// disasm_obj.mach = bfd_mach_m32c;
	disasm_obj.disassembler_options = "";
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &m32c_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.buffer_vma = Offset;
	disasm_obj.buffer_length = R_MIN (len, sizeof (bytes));
	disasm_obj.endian = !a->config->big_endian;
	disasm_obj.endian_code = disasm_obj.endian;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;
	op->size = print_insn_m32c ((bfd_vma)Offset, &disasm_obj);
	if (op->size == -1) {
		op->mnemonic = strdup ("(data)");
		// r_strbuf_set (&op->buf_asm, "(data)");
		r_strbuf_free (buf_global);
	} else {
		op->mnemonic = r_strbuf_drain (buf_global);
	}
	return op->size;
}

static int m32c_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *b, int len, RAnalOpMask mask) {
	if (!op) {
		return 1;
	}
	op->size = 4;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->addr = addr;
		disassemble (anal, op, b, len);
	}

	return op->size;
}

RAnalPlugin r_anal_plugin_m32c = {
	.name = "m32c",
	.desc = "m32c analysis plugin",
	.license = "LGPL-3.0-only",
	.arch = "m32c",
	.esil = false,
	.bits = 32,
	.op = &m32c_op,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_m32c,
	.version = R2_VERSION
};
#endif
