/* example r_asm plugin by pancake at 2014 */

#include <r_asm.h>
#include <r_lib.h>

#define OPS 17

static const char *ops[OPS*2] = {
	"nop", NULL,
	"if", "r",
	"ifnot", "r",
	"add", "rr",
	"addi", "ri",
	"sub", "ri",
	"neg", "ri",
	"xor", "ri",
	"mov", "ri",
	"cmp", "rr",
	"load", "ri",
	"store", "ri",
	"shl", "ri",
	"br", "r",
	"bl", "r",
	"ret", NULL,
	"sys", "i"
};

static int disassemble (RAsm *a, RAsmOp *op, const ut8 *b, int l) {
	char arg[32];
	int idx = (b[0]&0xf)*2;
	op->size = 2;
	if (idx>=(OPS*2)) {
		r_strbuf_set (&op->buf_asm, "invalid");
		return -1;
	}
	r_strbuf_set (&op->buf_asm, ops[idx]);
	if (ops[idx+1]) {
		const char *p = ops[idx+1];
		arg[0] = 0;
		if (!strcmp (p, "rr")) {
			sprintf (arg, "r%d, r%d", b[1]>>4, b[1]&0xf);
		} else
		if (!strcmp (p, "i")) {
			sprintf (arg, "%d", (char)b[1]);
		} else
		if (!strcmp (p, "r")) {
			sprintf (arg, "r%d, r%d", b[1]>>4, b[1]&0xf);
		} else
		if (!strcmp (p, "ri")) {
			sprintf (arg, "r%d, %d", b[1]>>4, (char)b[1]&0xf);
		}
		if (*arg) {
			r_strbuf_append (&op->buf_asm, " ");
			r_strbuf_append (&op->buf_asm, arg);
		}
	}
	return op->size;
}

RAsmPlugin r_asm_plugin_mycpu = {
        .name = "mycpu",
        .arch = "mycpu",
        .license = "LGPL3",
        .bits = 32,
        .desc = "My CPU disassembler",
        .disassemble = &disassemble,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
        .type = R_LIB_TYPE_ASM,
        .data = &r_asm_plugin_mycpu
};
#endif
