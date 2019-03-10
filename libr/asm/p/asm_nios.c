/* nios plugin by hewittc at 2018 */

#include <r_asm.h>
#include <r_lib.h>
#include <r_types.h>
#include <r_util.h>

#include "dis-asm.h"

#include "nios/gnu/nios-desc.h"

static RStrBuf *buf_global = NULL;
static ut8 bytes[2];

static int nios_buffer_read_memory(bfd_vma address, bfd_byte *byte, ut32 len, disassemble_info *info) {
	memcpy(byte, bytes, len);
	return 0;
}

static int nios_symbol_at_address(bfd_vma address, disassemble_info *info) {
	return 0;
}

static void nios_memory_error(int status, bfd_vma address, disassemble_info *info) {
	//--
}

static void nios_print_address(bfd_vma address, disassemble_info *info) {
	if (buf_global) {
		r_strbuf_appendf (buf_global, "0x%08"PFMT64x, (ut64) address);
	}
}

static int nios_fprintf(void *stream, const char *format, ...) {
	if (!buf_global) {
		return 0;
	}

	va_list args;
	va_start(args, format);
	r_strbuf_vappendf (buf_global, format, args);
	va_end(args);

	return 0;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	if (len < 2) {
		return -1;
	}

	buf_global = &op->buf_asm;
	memcpy(bytes, buf, 2);

	struct disassemble_info info = {0};

	info.disassembler_options = "";
	info.mach = a->bits == 16 ? MACH_NIOS16 : MACH_NIOS32;
	info.buffer = bytes;
	info.read_memory_func = &nios_buffer_read_memory;
	info.symbol_at_address_func = &nios_symbol_at_address;
	info.memory_error_func = &nios_memory_error;
	info.print_address_func = &nios_print_address;
	info.endian = !a->big_endian;
	info.fprintf_func = &nios_fprintf;
	info.stream = stdout;

	op->size = print_insn_nios((bfd_vma) a->pc, &info);

	if (op->size == -1) {
		r_strbuf_set(&op->buf_asm, " (data)");
	}

	return op->size;
}

RAsmPlugin r_asm_plugin_nios = {
	.name = "nios",
	.arch = "nios",
	.desc = "Nios embedded processor",
	.license = "GPL3",
	.bits = 16 | 32,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_nios,
	.version = R2_VERSION
};
#endif
