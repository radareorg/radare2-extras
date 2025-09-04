#include <r_lib.h>
#include <r_arch.h>

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
    op->type = R_ANAL_OP_TYPE_UNK;
    if (mask & R_ARCH_OP_MASK_DISASM) op->mnemonic = strdup("(mc6809: unimplemented)");
    op->size = 1;
    return true;
}

static int info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_MINOP_SIZE: return 1;
    case R_ARCH_INFO_MAXOP_SIZE: return 3;
    default: return 1;
    }
}

RArchPlugin r_arch_plugin_mc6809 = {
    .meta = {
        .name = "mc6809",
        .desc = "Motorola 6809 (stub)",
        .author = "radare2-extras",
        .version = R2_VERSION,
        .license = "LGPL3",
        .status = R_PLUGIN_STATUS_BASIC,
    },
    .arch = "mc6809",
    .bits = R_SYS_BITS_PACK1(8),
    .endian = R_SYS_ENDIAN_BIG,
    .info = &info,
    .decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ARCH,
    .data = &r_arch_plugin_mc6809,
    .version = R2_VERSION
};
#endif
