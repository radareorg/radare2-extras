#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "pyc_dis.h"

static int disassemble (RAsm *a, RAsmOp *opstruct, const ut8 *buf, int len) {
	RList *interned_table = NULL;
	RList *shared = NULL;
	RList *cobjs = NULL;

	RBin *bin = a->binb.bin;
	ut64 pc = a->pc;

	RBinPlugin *plugin = bin && bin->cur && bin->cur->o ?
		bin->cur->o->plugin : NULL;

	if (plugin) {
		if (!strcmp (plugin->name, "pyc")) {
			shared = bin->cur->o->bin_obj;
		}
	}
	cobjs = r_list_get_n (shared, 0);
	interned_table = r_list_get_n (shared, 1);
	int r = r_pyc_disasm (opstruct, buf, cobjs, interned_table, pc);
	opstruct->size = r;
	return r;
}

static int dis (RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
    const char *buf_asm = "invalid";
    int size = -1;

    if (op_name[buf[0]]) {
        if (HAS_ARG(buf[0])) {
            if (a->bits == 16) {
                ut16 operand = (buf[2] << 8) | buf[1];
                buf_asm = sdb_fmt ("%s %d",op_name[buf[0]], operand);
                size = 3; // < 3.6
            } else {
                buf_asm = sdb_fmt ("%s %d",op_name[buf[0]], buf[1]);
                size = 2; // >= 3.6
            }
        } else {
            buf_asm = sdb_fmt (op_name[buf[0]]);
            if (buf[1] == STOP_CODE) {
                size = 2;
            } else {
                size = 1;
            }
        }
    }
//    eprintf("kmbs: f:%s\tbuf_asm:%s\n",__func__,buf_asm);

    r_strbuf_set (&op->buf_asm, buf_asm);
    op->size = size;
    return size;
}

static bool init (void *user) {
	init_opname_table ();
	return true;
}

RAsmPlugin r_asm_plugin_pyc = {
	.name = "pyc",
	.arch = "pyc",
	.license = "LGPL3",
	.bits = 16 | 8,
	.desc = "PYC disassemble plugin",
	.disassemble = &dis,
	.init = &init,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_pyc,
	.version = R2_VERSION
};

#endif
