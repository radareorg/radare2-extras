#include <r_lib.h>
#include <r_arch.h>
#include <r_util.h>
#include "msil/demsil.c"

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
    if (!(mask & R_ARCH_OP_MASK_DISASM)) {
        op->size = 0;
        return true;
    }
    ut32 n;
    ILOPCODE_STRUCT ilopar[8];
    int o = DisasMSIL(op->bytes, op->size, op->addr, ilopar, 8, &n);
    if (o <= 0) {
        op->type = R_ANAL_OP_TYPE_ILL;
        op->size = 0;
        op->mnemonic = strdup("invalid");
        return false;
    }
    op->size = o;
    op->mnemonic = strdup(ilopar[0].Mnemonic);
    return true;
}

static int info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_MINOP_SIZE: return 1;
    case R_ARCH_INFO_MAXOP_SIZE: return 8;
    default: return 1;
    }
}

RArchPlugin r_arch_plugin_msil = {
    .meta = {
        .name = "msil",
        .desc = "Microsoft IL",
        .author = "capi_x, pancake",
        .version = R2_VERSION,
        .license = "PD",
        .status = R_PLUGIN_STATUS_OK,
    },
    .arch = "msil",
    .bits = R_SYS_BITS_PACK3(16, 32, 64),
    .endian = R_SYS_ENDIAN_LITTLE,
    .info = &info,
    .decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ARCH,
    .data = &r_arch_plugin_msil,
    .version = R2_VERSION
};
#endif

