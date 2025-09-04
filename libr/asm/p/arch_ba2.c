/* RArch plugin for BA2 using local disassembler */
#include <r_lib.h>
#include <r_arch.h>
#include <r_util.h>
#include <string.h>

#include "../arch/ba2/ba2_disas.c"

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
    struct op_cmd cmd = { .instr = "", .operands = "" };
    int ret = ba2_decode_opcode(op->addr, op->bytes, op->size, &cmd, NULL, NULL);
    if ((op->size < ret) || (!ret && op->size < 6)) {
        if (mask & R_ARCH_OP_MASK_DISASM) op->mnemonic = strdup("truncated");
        op->size = 0;
        op->type = R_ANAL_OP_TYPE_ILL;
        return false;
    }
    if (ret > 0) {
        if (mask & R_ARCH_OP_MASK_DISASM) {
            char buf[128];
            if (*cmd.operands) snprintf(buf, sizeof(buf), "%s %s", cmd.instr, cmd.operands);
            else snprintf(buf, sizeof(buf), "%s", cmd.instr);
            op->mnemonic = strdup(buf);
        }
        op->size = ret;
        return true;
    }
    if (mask & R_ARCH_OP_MASK_DISASM) op->mnemonic = strdup("invalid");
    op->size = 0;
    op->type = R_ANAL_OP_TYPE_ILL;
    return false;
}

static int info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_MINOP_SIZE: return 2;
    case R_ARCH_INFO_MAXOP_SIZE: return 8;
    default: return 2;
    }
}

RArchPlugin r_arch_plugin_ba2 = {
    .meta = {
        .name = "ba2",
        .desc = "Beyond Architecture 2 disassembler",
        .author = "radare2-extras",
        .version = R2_VERSION,
        .license = "LGPL3",
        .status = R_PLUGIN_STATUS_OK,
    },
    .arch = "ba2",
    .bits = R_SYS_BITS_PACK1(32),
    .endian = R_SYS_ENDIAN_LITTLE,
    .info = &info,
    .decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ARCH,
    .data = &r_arch_plugin_ba2,
    .version = R2_VERSION
};
#endif
