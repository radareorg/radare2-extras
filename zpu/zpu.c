/* zpu plugin by saucec0de at 2016 */

#include <r_asm.h>
#include <r_lib.h>

static int disassemble (RAsm *a, RAsmOp *op, const ut8 *b, int l) {
	char arg[100];
	ut8 instr = b[0];

	op->size = 1;

	// 000x xxxx
	if ( (instr & 0xe0) == 0x00 ) {
		switch ( instr & 0x1f ) {
			case 0x0: strcpy (op->buf_asm, "BRK");     break;
			case 0x1: strcpy (op->buf_asm, "unknown"); break;
			case 0x2: strcpy (op->buf_asm, "PUSHSP");  break;
			case 0x3: strcpy (op->buf_asm, "unknown"); break;
			case 0x4: strcpy (op->buf_asm, "POPPC");   break;
			case 0x5: strcpy (op->buf_asm, "ADD");     break;
			case 0x6: strcpy (op->buf_asm, "AND");     break;
			case 0x7: strcpy (op->buf_asm, "OR");      break;
			case 0x8: strcpy (op->buf_asm, "LOAD");    break;
			case 0x9: strcpy (op->buf_asm, "NOT");     break;
			case 0xa: strcpy (op->buf_asm, "FLIP");    break;
			case 0xb: strcpy (op->buf_asm, "NOP");     break;
			case 0xc: strcpy (op->buf_asm, "STORE");   break;
			case 0xd: strcpy (op->buf_asm, "POPSP");   break;
			case 0xe: strcpy (op->buf_asm, "unknown"); break;
			case 0xf: strcpy (op->buf_asm, "unknown"); break;
			default:
		strcpy (op->buf_asm, "ADDTOP ");
		sprintf (arg, "%d", instr & 0x0f);
		strcat (op->buf_asm, arg);
		break;
		}
		return 1;
	}
	// 001x xxxx
	if ( (instr & 0xe0) == 0x20 ) {
		strcpy (op->buf_asm, "EMULATE ");
		sprintf (arg, "%d", instr & 0x1f);
		strcat (op->buf_asm, arg);
		return 1;
	}
	// 010x xxxx
	if ( (instr & 0xe0) == 0x40 ) {
		int val = instr & 0x1f;
		val ^= 0x10;
		if (val == 0) {
			strcpy (op->buf_asm, "POP");
			return 1;
		}
		if (val == 1) {
			strcpy (op->buf_asm, "POPDOWN");
			return 1;
		}
		strcpy (op->buf_asm, "STORESP ");
		sprintf (arg, "%d", val);
		strcat (op->buf_asm, arg);
		return 1;
	}
	// 011x xxxx
	if ( (instr & 0xe0) == 0x40 ) {
		int val = instr & 0x1f;
		val ^= 0x10;
		if (val == 0) {
			strcpy (op->buf_asm, "DUP");
			return 1;
		}
		if (val == 1) {
			strcpy (op->buf_asm, "DUPSTACKB");
			return 1;
		}
		strcpy (op->buf_asm, "LOADSP ");
		sprintf (arg, "%d", val);
		strcat (op->buf_asm, arg);
		return 1;
	}
	strcpy (op->buf_asm, "IM ");
	sprintf (arg, "%d", instr & 0x7f);
	strcat (op->buf_asm, arg);
	return 1;
}

RAsmPlugin r_asm_plugin_zpu = {
	.name = "zpu",
	.arch = "zpu",
	.license = "LGPL3",
	.bits = 32,
	.desc = "ZPU disassembler",
	.disassemble = &disassemble,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_zpu
};
#endif
