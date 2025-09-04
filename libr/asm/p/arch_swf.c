#include <r_lib.h>
#include <r_arch.h>
#include <r_util.h>
#include "../arch/swf/swfdis.h"

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
    if (!(mask & R_ARCH_OP_MASK_DISASM)) {
        op->size = 0;
        return true;
    }
    if (!as || !as->arch || !as->arch->binb.bin || !as->arch->binb.bin->cur) {
        op->mnemonic = strdup("invalid");
        op->type = R_ANAL_OP_TYPE_ILL;
        return false;
    }
    RBin *bin = as->arch->binb.bin;
    RBinObject *obj = bin->cur ? bin->cur->bo : NULL;
    if (!obj) {
        op->mnemonic = strdup("invalid");
        op->size = 0;
        return false;
    }
    RStrBuf sb;
    r_strbuf_init(&sb);
    int dlen = r_asm_swf_disass(obj, &sb, op->bytes, op->size, op->addr);
    op->size = dlen > 0 ? dlen : 0;
    op->mnemonic = r_strbuf_drain(&sb);
    return dlen > 0;
}

static int info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_MINOP_SIZE: return 1;
    case R_ARCH_INFO_MAXOP_SIZE: return 8;
    default: return 1;
    }
}

RArchPlugin r_arch_plugin_swf = {
    .meta = {
        .name = "swf",
        .desc = "SWF",
        .author = "xarkes, pancake",
        .version = R2_VERSION,
        .license = "LGPL3",
        .status = R_PLUGIN_STATUS_OK,
    },
    .arch = "swf",
    .bits = R_SYS_BITS_PACK1(32),
    .endian = R_SYS_ENDIAN_LITTLE,
    .info = &info,
    .decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ARCH,
    .data = &r_arch_plugin_swf,
    .version = R2_VERSION
};
#endif
