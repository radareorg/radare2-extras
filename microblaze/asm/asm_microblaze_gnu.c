/* GPL, Copyright 2015 - tic */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "dis-asm.h"

static unsigned long Offset = 0;
static char *buf_global = NULL;
static unsigned char bytes[4];

static int microblaze_buffer_read_memory (bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, struct disassemble_info *info) {
	memcpy (myaddr, bytes, length);
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info * info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
}

static void print_address(bfd_vma address, struct disassemble_info *info) {
	char tmp[32];
	if (buf_global == NULL)
		return;
	sprintf (tmp, "0x%08"PFMT64x, (ut64)address);
	strcat (buf_global, tmp);
}

static int buf_fprintf(void *stream, const char *format, ...) {
	va_list ap;
	char *tmp;
	if (buf_global == NULL || format == NULL)
		return false;
	va_start (ap, format);
 	tmp = malloc (strlen (format)+strlen (buf_global)+2);
	if (tmp == NULL) {
		va_end (ap);
		return false;
	}
	sprintf (tmp, "%s%s", buf_global, format);
	vsprintf (buf_global, tmp, ap);
	va_end (ap);
	free (tmp);
	return true;
}

static int disassemble(struct r_asm_t *a, struct r_asm_op_t *op, const ut8 *buf, int len) {

	static struct disassemble_info disasm_obj;
	if (len<4) return -1;

	buf_global = op->buf_asm;
	Offset = a->pc;
	if (Offset % 4) return -1;

	memcpy (bytes, buf, 4);

	/* prepare disassembler */
	memset (&disasm_obj,'\0', sizeof (struct disassemble_info));
	disasm_obj.arch = 0;
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &microblaze_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &print_address;
	disasm_obj.buffer_vma = Offset;
	disasm_obj.buffer_length = 4;
	//disasm_obj.endian = a->big_endian ? BFD_ENDIAN_BIG : BFD_ENDIAN_LITTLE;
    // only support little endian for now
	disasm_obj.endian = !a->big_endian;
	disasm_obj.fprintf_func = &buf_fprintf;
	disasm_obj.stream = stdout;

	op->buf_asm[0] = '\0';
	op->size = print_insn_microblaze ((bfd_vma)Offset, &disasm_obj);
	if (op->size == -1)
		op->size = 4;
	return op->size;
}

RAsmPlugin r_asm_plugin_microblaze_gnu = {
	.name = "microblaze.gnu",
	.arch = "microblaze",
	.license = "GPL3",
	.bits = 32,
	.desc = "MICROBLAZE CPU",
	.disassemble = &disassemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_microblaze_gnu,
	.version = R2_VERSION
};
#endif
