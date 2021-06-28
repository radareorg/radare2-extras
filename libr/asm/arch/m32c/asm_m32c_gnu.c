/* radare - LGPL - Copyright 2021 - pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

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
	if ((delta + length) > 4) {
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

static int disassemble(struct r_asm_t *a, struct r_asm_op_t *op, const ut8 *buf, int len) {
	static struct disassemble_info disasm_obj;
	if (len < 4) {
		return -1;
	}
	buf_global = &op->buf_asm;
	Offset = a->pc;
	memcpy (bytes, buf, R_MIN (len, sizeof (bytes))); // TODO handle thumb

	if ((a->cpu != pre_cpu) && (a->features != pre_features)) {
		free (disasm_obj.disassembler_options);
		memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	}	

	/* prepare disassembler */
	disasm_obj.mach = bfd_mach_m32c;
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &m32c_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.buffer_vma = Offset;
	disasm_obj.buffer_length = R_MIN (len, sizeof (bytes));
	disasm_obj.endian = !a->big_endian;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;
	op->size = print_insn_m32c ((bfd_vma)Offset, &disasm_obj);
	if (op->size == -1) {
		r_strbuf_set (&op->buf_asm, "(data)");
	}
	return op->size;
}

#if 0
static int assemble(RAsm *a, RAsmOp *op, const char *str) {
	ut8 *opbuf = (ut8*)r_strbuf_get (&op->buf);
	int ret = m32c_assemble (str, a->pc, opbuf);
	if (a->big_endian) {
		ut8 tmp = opbuf[0];
		opbuf[0] = opbuf[3];
		opbuf[3] = tmp;
		tmp = opbuf[1];
		opbuf[1] = opbuf[2];
		opbuf[2] = tmp;
	}
	return ret;
}
#endif

RAsmPlugin r_asm_plugin_m32c_gnu = {
	.name = "m32c.gnu",
	.arch = "m32c",
	.license = "GPL3",
	.bits = 16 | 32,
	.endian = R_SYS_ENDIAN_LITTLE,
	.desc = "M32C CPU",
	.disassemble = &disassemble,
// 	.assemble = &assemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_m32c_gnu,
	.version = R2_VERSION
};
#endif
