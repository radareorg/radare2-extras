#include <r_lib.h>
#include <r_arch.h>
#include <r_util.h>
#include "../arch/atombios/atombios.h"

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
    if (!(mask & R_ARCH_OP_MASK_DISASM)) {
        op->size = 0;
        return true;
    }
    char out[1024];
    out[0] = 0;
    int sz = atombios_disassemble(op->bytes, op->size, out);
    if (sz <= 0) {
        op->mnemonic = strdup("invalid");
        op->size = 0;
        return false;
    }
    op->mnemonic = strdup(out);
    op->size = sz;
    return true;
}

static int info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_MINOP_SIZE: return 1;
    case R_ARCH_INFO_MAXOP_SIZE: return 8;
    default: return 1;
    }
}

RArchPlugin r_arch_plugin_atombios = {
    .meta = {
        .name = "atombios",
        .desc = "AtomBIOS",
        .author = "damo22",
        .version = R2_VERSION,
        .license = "LGPL3",
        .status = R_PLUGIN_STATUS_OK,
    },
    .arch = "atombios",
    .bits = R_SYS_BITS_PACK3(16, 32, 64),
    .endian = R_SYS_ENDIAN_NONE,
    .info = &info,
    .decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ARCH,
    .data = &r_arch_plugin_atombios,
    .version = R2_VERSION
};
#endif
