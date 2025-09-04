#include <r_lib.h>
#include <r_arch.h>
#include <r_util.h>

#include "../arch/z80_nc/disasm.c"

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
    if (mask & R_ARCH_OP_MASK_DISASM) {
        char out[128];
        int dlen = z80dis(0, op->bytes, out, op->size);
        if (dlen < 0) dlen = 0;
        op->size = dlen;
        op->mnemonic = strdup(out);
        return dlen > 0;
    }
    return true;
}

static int info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_MINOP_SIZE: return 1;
    case R_ARCH_INFO_MAXOP_SIZE: return 4;
    default: return 1;
    }
}

RArchPlugin r_arch_plugin_z80_nc = {
    .meta = {
        .name = "z80.nc",
        .desc = "Zilog Z80 non-commercial",
        .author = "pancake",
        .version = R2_VERSION,
        .license = "NC-GPL2",
        .status = R_PLUGIN_STATUS_OK,
    },
    .arch = "z80",
    .bits = R_SYS_BITS_PACK1(8),
    .endian = R_SYS_ENDIAN_NONE,
    .info = &info,
    .decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ARCH,
    .data = &r_arch_plugin_z80_nc,
    .version = R2_VERSION
};
#endif
