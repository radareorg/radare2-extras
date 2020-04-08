/* radare - LGPL3 - Copyright 2016-2020 - FXTi */

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "../../asm/arch/pyc/opcode.h"

static int archinfo (RAnal *anal, int query) {
    if (!strcmp (anal->cpu, "x86")) {
        return -1;
    } else {
        switch (query) {
        case R_ANAL_ARCHINFO_MIN_OP_SIZE:
                return (anal->bits == 16) ? 1 : 2;
        case R_ANAL_ARCHINFO_MAX_OP_SIZE:
                return (anal->bits == 16) ? 3 : 2;
        default:
                return -1;
        }
    }
}

static char *get_reg_profile(RAnal *anal) {
    return strdup (
        "=PC    pc\n"
        "=BP    bp\n"
        "=SP    sp\n"
        "gpr    sp  .32 0   0\n" // stack pointer
        "gpr    pc  .32 4   0\n" // program counter
        "gpr    bp  .32 8   0\n" // base pointer // unused
    );
}

static int pyc_op (RAnal *a, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
    ut32 extended_arg = 0, oparg;
    ut8 op_code = data[0];
    pyc_opcodes *ops;
    op->jump = UT64_MAX;
    op->fail = UT64_MAX;
    op->ptr = op->val = UT64_MAX;
    op->addr = addr;
    op->sign = true;
    op->type = R_ANAL_OP_TYPE_UNK;
    op->id = op_code;

    if (!(ops = get_opcode_by_version (a->cpu))) {
        return -1;
    }
    bool is_python36 = a->bits == 8;
    pyc_opcode_object *op_obj = &ops->opcodes[op_code];
    if (!op_obj->op_name) {
        op->type = R_ANAL_OP_TYPE_ILL;
        op->size = 1;
        goto anal_end;
    }

    if (is_python36) {
        op->size = 2;
    } else {
        op->size = (op_code >= ops->have_argument) ? 3 : 1;
    }

	if (op_code >= ops->have_argument) {
		if (!is_python36) {
			oparg = data[1] + data[2] * 256 + extended_arg;
		} else {
			oparg = data[1] + extended_arg;
		}
		extended_arg = 0;
		if (op_code == ops->extended_arg) {
			if (!is_python36) {
				extended_arg = oparg * 65536; // what should be done for EXTENDED_ARG???
			} else {
				extended_arg = oparg << 8;
			}
		}
	} 

    if (op_obj->type & HASJABS) {
        op->type = R_ANAL_OP_TYPE_JMP;
        op->jump = oparg;

        if (op_obj->type & HASCONDITION) {
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->fail = addr + ((is_python36) ? 2 : 3);
        } 
        goto anal_end;
    }
    if (op_obj->type & HASJREL) {
        op->type = R_ANAL_OP_TYPE_JMP;
        op->jump = addr + oparg + ((is_python36) ? 2 : 3);

        if (op_obj->type & HASCONDITION) {
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->fail = addr + ((is_python36) ? 2 : 3);
        } 
        goto anal_end;
    }

    if (op_obj->type & HASCOMPARE) {
        op->type = R_ANAL_OP_TYPE_CMP;
        goto anal_end;
    }

    anal_pyc_op(op, op_obj, oparg);

anal_end:
    free_opcode (ops);
    return op->size;
}

RAnalPlugin r_anal_plugin_pyc = {
    .name = "pyc",
    .desc = "Python bytecode analysis plugin",
    .license = "LGPL3",
    .arch = "pyc",
    .bits = 16 | 8, // Partially agree with this
    .archinfo = archinfo,
    .get_reg_profile = get_reg_profile,
    .op = &pyc_op,
    .esil = false,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
    .type = R_LIB_TYPE_ANAL,
    .data = &r_anal_plugin_pyc,
    .version = R2_VERSION
};
#endif
