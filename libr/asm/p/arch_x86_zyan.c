#include <r_lib.h>
#include <r_arch.h>

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
    if (mask & R_ARCH_OP_MASK_DISASM) op->mnemonic = strdup("(zydis: unavailable on this host)");
    op->size = 0;
    return false;
}

static int info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_MINOP_SIZE: return 1;
    case R_ARCH_INFO_MAXOP_SIZE: return 15;
    default: return 1;
    }
}

RArchPlugin r_arch_plugin_x86_zyan = {
    .meta = {
        .name = "x86.zyan",
        .desc = "x86 Zydis disassembler (stub on non-x86)",
        .author = "mrexodia",
        .version = R2_VERSION,
        .license = "MIT",
        .status = R_PLUGIN_STATUS_BASIC,
    },
    .arch = "x86",
    .bits = R_SYS_BITS_PACK3(16, 32, 64),
    .endian = R_SYS_ENDIAN_LITTLE,
    .info = &info,
    .decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ARCH,
    .data = &r_arch_plugin_x86_zyan,
    .version = R2_VERSION
};
#endif
