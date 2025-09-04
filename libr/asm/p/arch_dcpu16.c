#include <r_lib.h>
#include <r_arch.h>

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
    op->type = R_ANAL_OP_TYPE_UNK;
    if (mask & R_ARCH_OP_MASK_DISASM) op->mnemonic = strdup("(dcpu16: unimplemented)");
    op->size = 2;
    return true;
}

static int info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_MINOP_SIZE: return 2;
    case R_ARCH_INFO_MAXOP_SIZE: return 4;
    default: return 2;
    }
}

RArchPlugin r_arch_plugin_dcpu16 = {
    .meta = {
        .name = "dcpu16",
        .desc = "DCPU-16 (stub)",
        .author = "radare2-extras",
        .version = R2_VERSION,
        .license = "LGPL3",
        .status = R_PLUGIN_STATUS_BETA,
    },
    .arch = "dcpu16",
    .bits = R_SYS_BITS_PACK1(16),
    .endian = R_SYS_ENDIAN_LITTLE,
    .info = &info,
    .decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ARCH,
    .data = &r_arch_plugin_dcpu16,
    .version = R2_VERSION
};
#endif

