#include <r_lib.h>
#include <r_arch.h>
#include <r_util.h>
#include <psosvm/vmas/vmas.h>

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
    char buf_asm[64] = {0};
    psosvmasm_init();
    int sz = psosvm_disasm(op->bytes, buf_asm);
    if (sz > 0) {
        if (mask & R_ARCH_OP_MASK_DISASM) op->mnemonic = strdup(buf_asm);
        op->size = sz;
        return true;
    }
    if (mask & R_ARCH_OP_MASK_DISASM) op->mnemonic = strdup("(data)");
    op->size = 0;
    return false;
}

static int info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_MINOP_SIZE: return 1;
    case R_ARCH_INFO_MAXOP_SIZE: return 4;
    default: return 1;
    }
}

RArchPlugin r_arch_plugin_psosvm = {
    .meta = {
        .name = "psosvm",
        .desc = "Smartcard PSOSVM",
        .author = "nibble",
        .version = R2_VERSION,
        .license = "BSD",
        .status = R_PLUGIN_STATUS_OK,
    },
    .arch = "psosvm",
    .bits = R_SYS_BITS_PACK2(8, 16),
    .endian = R_SYS_ENDIAN_LITTLE,
    .info = &info,
    .decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ARCH,
    .data = &r_arch_plugin_psosvm,
    .version = R2_VERSION
};
#endif
