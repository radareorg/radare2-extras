/* RArch port of SPC700 disassembler (minimal text-only) */
#include <r_lib.h>
#include <r_arch.h>
#include <r_util.h>
#include <string.h>

#include "../arch/spc700/spc700_opcode_table.h"

static int op_len(int t) {
    switch (t) {
    case SPC_OP: return 1;
    case SPC_ARG8_1: return 2;
    case SPC_ARG8_2: return 3;
    case SPC_ARG16: return 3;
    }
    return 0;
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
    if (op->size < 1) {
        op->type = R_ANAL_OP_TYPE_ILL;
        if (mask & R_ARCH_OP_MASK_DISASM) {
            op->mnemonic = strdup("invalid");
        }
        return false;
    }
    int t = spc_op_table[op->bytes[0]].type;
    int len = op_len(t);
    if (op->size < len) {
        op->type = R_ANAL_OP_TYPE_UNK;
        op->size = 0;
        if (mask & R_ARCH_OP_MASK_DISASM) {
            op->mnemonic = strdup("(truncated)");
        }
        return false;
    }
    if (mask & R_ARCH_OP_MASK_DISASM) {
        const char *fmt = spc_op_table[op->bytes[0]].name;
        char buf[64];
        switch (t) {
        case SPC_OP:
            r_str_ncpy(buf, fmt, sizeof(buf));
            break;
        case SPC_ARG8_1:
            snprintf(buf, sizeof(buf), fmt, op->bytes[1]);
            break;
        case SPC_ARG8_2:
            snprintf(buf, sizeof(buf), fmt, op->bytes[1], op->bytes[2]);
            break;
        case SPC_ARG16:
            snprintf(buf, sizeof(buf), fmt, (int)(op->bytes[1] + 0x100 * op->bytes[2]));
            break;
        default:
            r_str_ncpy(buf, "invalid", sizeof(buf));
            break;
        }
        op->mnemonic = strdup(buf);
    }
    op->size = len;
    return true;
}

static int info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_MINOP_SIZE: return 1;
    case R_ARCH_INFO_MAXOP_SIZE: return 3;
    default: return 1;
    }
}

RArchPlugin r_arch_plugin_spc700 = {
    .meta = {
        .name = "spc700",
        .desc = "SPC700, SNES sound chip",
        .author = "condret, pancake",
        .version = R2_VERSION,
        .license = "LGPL3",
        .status = R_PLUGIN_STATUS_OK,
    },
    .arch = "spc700",
    .bits = R_SYS_BITS_PACK1(16),
    .endian = R_SYS_ENDIAN_NONE,
    .info = &info,
    .decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ARCH,
    .data = &r_arch_plugin_spc700,
    .version = R2_VERSION
};
#endif

