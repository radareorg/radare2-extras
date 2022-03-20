/* rl78 plugin by pancake, using binutils ripped code from 2022 */

#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <sdb.h>

#include "disas-asm.h"
#include "../arch/rl78/rl78-decode.c"
#include "../arch/rl78/rl78-dis.c"


static const char *rl78_reg_profile = \
	"=SR  ctl0\n"
	"=PC	pc\n"
	"=SP   r14\n"
	"=LR   r15\n"
	"=BP   r30\n"
	/* control registers */
	"gpr  ctl0      .16       0     0\n"
	"gpr  ctl1      .16       2     0\n"
	"gpr  ctl2      .16       4     0\n"
	"gpr  ctl3      .16       6     0\n"
	"gpr  ctl4      .16       8     0\n"
	"gpr  ctl5      .16      10     0\n"
	"gpr  ctl6      .16      12     0\n"
	"gpr  ctl7      .16      14     0\n"
	"gpr  ctl8      .16      16     0\n"
	"gpr  ctl9      .16      18     0\n"
	"gpr    pc      .16      20     0\n"
	"gpr     k      .16      22     0\n"
	/* r0-r7 are global (g0-g7) */
	"gpr    r0      .16      24     0\n"
	"gpr    r1      .16      26     0\n"
	"gpr    r2      .16      28     0\n"
	"gpr    r3      .16      30     0\n"
	"gpr    r4      .16      32     0\n"
	"gpr    r5      .16      34     0\n"
	"gpr    r6      .16      36     0\n"
	"gpr    r7      .16      38     0\n"
	/* r8-15 are out (o0-o7) */
	"gpr    r8      .16      40     0\n"
	"gpr    r9      .16      42     0\n"
	"gpr    r10     .16      44     0\n"
	"gpr    r11     .16      46     0\n"
	"gpr    r12     .16      48     0\n"
	"gpr    r13     .16      50     0\n"
	"gpr    r14     .16      52     0\n"
	"gpr    r15     .16      54     0\n"
	/* r16-23 are local (l0-l7) */
	"gpr    r16     .16      56     0\n"
	"gpr    r17     .16      58     0\n"
	"gpr    r18     .16      60     0\n"
	"gpr    r19     .16      62     0\n"
	"gpr    r20     .16      64     0\n"
	"gpr    r21     .16      66     0\n"
	"gpr    r22     .16      68     0\n"
	"gpr    r23     .16      70     0\n"
	/* r24-31 are in (i0-i7) */
	"gpr    r24     .16      72     0\n"
	"gpr    r25     .16      74     0\n"
	"gpr    r26     .16      76     0\n"
	"gpr    r27     .16      78     0\n"
	"gpr    r28     .16      80     0\n"
	"gpr    r29     .16      82     0\n"
	"gpr    r30     .16      84     0\n"
	"gpr    r31     .16      86     0\n";

static const char *rl7832_reg_profile = \
	"=SR  ctl0\n"
	"=PC	pc\n"
	"=SP   r14\n"
	"=LR   r15\n"
	"=BP   r30\n"
	/* control registers */
	"gpr  ctl0      .32       0     0\n"
	"gpr  ctl1      .32       4     0\n"
	"gpr  ctl2      .32       8     0\n"
	"gpr  ctl3      .32      12     0\n"
	"gpr  ctl4      .32      16     0\n"
	"gpr  ctl5      .32      20     0\n"
	"gpr  ctl6      .32      24     0\n"
	"gpr  ctl7      .32      28     0\n"
	"gpr  ctl8      .32      32     0\n"
	"gpr  ctl9      .32      36     0\n"
	"gpr    pc      .32      40     0\n"
	"gpr     k      .16      44     0\n"
	/* r0-r7 are global (g0-g7) */
	"gpr    r0      .32      48     0\n"
	"gpr    r1      .32      52     0\n"
	"gpr    r2      .32      56     0\n"
	"gpr    r3      .32      60     0\n"
	"gpr    r4      .32      64     0\n"
	"gpr    r5      .32      68     0\n"
	"gpr    r6      .32      72     0\n"
	"gpr    r7      .32      76     0\n"
	/* r8-15 are out (o0-o7) */
	"gpr    r8      .32      80     0\n"
	"gpr    r9      .32      84     0\n"
	"gpr    r10     .32      88     0\n"
	"gpr    r11     .32      92     0\n"
	"gpr    r12     .32      96     0\n"
	"gpr    r13     .32     100     0\n"
	"gpr    r14     .32     104     0\n"
	"gpr    r15     .32     108     0\n"
	/* r16-23 are local (l0-l7) */
	"gpr    r16     .32     112     0\n"
	"gpr    r17     .32     116     0\n"
	"gpr    r18     .32     120     0\n"
	"gpr    r19     .32     124     0\n"
	"gpr    r20     .32     128     0\n"
	"gpr    r21     .32     132     0\n"
	"gpr    r22     .32     136     0\n"
	"gpr    r23     .32     140     0\n"
	/* r24-31 are in (i0-i7) */
	"gpr    r24     .32     144     0\n"
	"gpr    r25     .32     148     0\n"
	"gpr    r26     .32     152     0\n"
	"gpr    r27     .32     156     0\n"
	"gpr    r28     .32     160     0\n"
	"gpr    r29     .32     164     0\n"
	"gpr    r30     .32     168     0\n"
	"gpr    r31     .32     172     0\n";

static unsigned long Offset = 0;
static RStrBuf *buf_global = NULL;
static const ut8 *bytes = NULL;
static int bytes_size = 0;

static int rl78_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - Offset);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	memcpy (myaddr, bytes + delta, R_MIN (length, bytes_size));
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC()
DECLARE_GENERIC_FPRINTF_FUNC()


static int rl78_op(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	if (!op) {
		return -1;
	}
	memset (op, 0, sizeof (RAnalOp));
	// RL78_ISA_G10
	// RL78_ISA_G13
	// RL78_ISA_G14
	disassemble_info disasm_obj = {0};
	memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	buf_global = r_strbuf_new ("");
	bytes = data;
	bytes_size = len;
	Offset = 0; // a->pc;
	disasm_obj.buffer = (ut8*)bytes;
	disasm_obj.read_memory_func = &rl78_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = BFD_ENDIAN_LITTLE;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;
	op->size = print_insn_rl78 ((bfd_vma)Offset, &disasm_obj);
	int res = print_insn_rl78_common (addr, &disasm_obj, RL78_ISA_DEFAULT);
	if (mask & R_ANAL_OP_MASK_DISASM) {
		op->mnemonic = r_strbuf_drain (buf_global);
	}

	op->size = 1; // CGEN_MAX_INSN_SIZE;
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;

	return op->size;
}

RAnalPlugin r_anal_plugin_rl78 = {
	.name = "rl78",
	.desc = "Renesas RL78 8 bit CPU",
	.license = "LGPL3",
	.arch = "rl78",
	.bits = 8,
	.esil = false,
	.op = &rl78_op,
	// .set_reg_profile = &set_reg_profile,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_rl78,
	.version = R2_VERSION
};
#endif

