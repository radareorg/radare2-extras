/* radare - GPL3 - Copyright 2015 pancake */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "blackfin/bfin-dis.c"
#include "blackfin/bfin-asm.c"

static unsigned long Offset = 0;
static RStrBuf *buf_global = NULL;
static unsigned char bytes[8]; // Allow for parallel combination of instructions: 4 bytes + 2 bytes + 2 bytes

static int bfin_buffer_read_memory (bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) 
{
        memcpy (myaddr, bytes+memaddr-Offset, length);
        return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info * info) 
{
        return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) 
{
        //--
}


static void print_address(bfd_vma address, struct disassemble_info *info) 
{
        if (buf_global == NULL)
                return;
        r_strbuf_appendf (buf_global, "0x%08"PFMT64x"", (ut64)address);
}


static int buf_fprintf(void *stream, const char *format, ...) 
{
        va_list ap;
        if (buf_global == NULL)
                return 0;
        va_start (ap, format);
        r_strbuf_vappendf (buf_global, format, ap);
        va_end (ap);
        return 0;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) 
{
        struct disassemble_info disasm_obj;
        r_strbuf_set (&op->buf_asm, "");
	op->size = 4;
        if (len<2)
                return -1;
        buf_global = &op->buf_asm;
        Offset = a->pc;
        if (len<8) memcpy (bytes, buf, len);
	else memcpy (bytes, buf, 8);

        /* prepare disassembler */
        memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
        disasm_obj.disassembler_options=(a->bits==64)?"64":"";
        disasm_obj.buffer = bytes;
        disasm_obj.read_memory_func = &bfin_buffer_read_memory;
        disasm_obj.symbol_at_address_func = &symbol_at_address;
        disasm_obj.memory_error_func = &memory_error_func;
        disasm_obj.print_address_func = &print_address;
        disasm_obj.endian = !a->big_endian;
        disasm_obj.fprintf_func = &buf_fprintf;
        disasm_obj.stream = stdout;

	op->size = print_insn_bfin((bfd_vma)Offset, &disasm_obj);

        if (op->size == -1)
                r_strbuf_set (&op->buf_asm, " (data)");

        return op->size;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) 
{
	ut8 hexbuf[8];
	int oplen;

	r_asm_op_init(op);

	oplen=bfin_assemble(buf, (uint32_t)(a->pc), hexbuf);

	r_asm_op_set_hexbuf(op, hexbuf, oplen);

	return op->buf.len;
}

static bool init(void *user)
{
	return 0;
}

RAsmPlugin r_asm_plugin_blackfin = {
	.name = "blackfin",
	.arch = "blackfin",
	.bits = 32,
	.desc = "Blackfin Analog Devices",
	.init = &init,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_blackfin,
	.version = R2_VERSION
};
#endif
