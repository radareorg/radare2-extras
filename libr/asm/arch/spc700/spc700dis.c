/* radare - LGPL - Copyright 2014 - condret@runas-racer.com */

#include <r_types.h>
#include <r_asm.h>
#include <stdio.h>
#include <string.h>
#include "spc700_opcode_table.h"

static int spc700OpLength(int spcoptype){
	switch(spcoptype) {
	case SPC_OP:
		return 1;
	case SPC_ARG8_1:
		return 2;
	case SPC_ARG8_2:
	case SPC_ARG16:
		return 3;
	}
	return 0;
}

static int spc700Disass(RAsmOp *op, const ut8 *buf, int len) {
	int foo = spc700OpLength (spc_op_table[buf[0]].type);
	r_strf_buffer (256);
	if (len < foo) {
		return 0;
	}
	const char *buf_asm = "invalid";
	switch (spc_op_table[buf[0]].type) {
	case SPC_OP:
		buf_asm = spc_op_table[buf[0]].name;
		break;
	case SPC_ARG8_1:
		buf_asm = r_strf (spc_op_table[buf[0]].name, buf[1]);
		break;
	case SPC_ARG8_2:
		buf_asm = r_strf (spc_op_table[buf[0]].name, buf[1], buf[2]);
		break;
	case SPC_ARG16:
		buf_asm = r_strf (spc_op_table[buf[0]].name, buf[1]+0x100*buf[2]);
		break;
	}
	r_asm_op_set_asm (op, buf_asm);
	return foo;
}
