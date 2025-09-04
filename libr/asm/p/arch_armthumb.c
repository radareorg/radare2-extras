#include <r_lib.h>
#include <r_arch.h>
#include "../arch/arm/arm.h"

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
    int *p = (int*)op->bytes; // thumb is 16-bit, using host endianness assumption here
    char buf_asm[64] = {0};
    int len = armthumb_disassemble(buf_asm, (ut32)op->addr, *p);
    if (len <= 0) {
        op->type = R_ANAL_OP_TYPE_UNK;
        op->size = 0;
        if (mask & R_ARCH_OP_MASK_DISASM) op->mnemonic = strdup("(data)");
        return false;
    }
    op->size = len;
    if (mask & R_ARCH_OP_MASK_DISASM) op->mnemonic = strdup(buf_asm);
    return true;
}

static int info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_MINOP_SIZE: return 2;
    case R_ARCH_INFO_MAXOP_SIZE: return 4;
    default: return 2;
    }
}

RArchPlugin r_arch_plugin_armthumb = {
    .meta = {
        .name = "arm.thumb",
        .desc = "ARM THUMB disassembler",
        .author = "pancake",
        .version = R2_VERSION,
        .license = "LGPL3",
        .status = R_PLUGIN_STATUS_OK,
    },
    .arch = "arm",
    .bits = R_SYS_BITS_PACK1(16),
    .endian = R_SYS_ENDIAN_LITTLE,
    .info = &info,
    .decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ARCH,
    .data = &r_arch_plugin_armthumb,
    .version = R2_VERSION
};
#endif

