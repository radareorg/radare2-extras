/* RArch plugin for x86 Olly disassembler */
#include <r_lib.h>
#include <r_arch.h>
#include <r_util.h>
#include "x86/ollyasm/disasm.h"

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
    t_disasm d = {0};
    int sz = Disasm_olly(op->bytes, op->size, op->addr, &d, DISASM_FILE);
    if (sz <= 0) {
        if (mask & R_ARCH_OP_MASK_DISASM) op->mnemonic = strdup("invalid");
        op->size = 0;
        return false;
    }
    if (mask & R_ARCH_OP_MASK_DISASM) op->mnemonic = strdup(d.result ? d.result : "");
    op->size = sz;
    return true;
}

static int info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_MINOP_SIZE: return 1;
    case R_ARCH_INFO_MAXOP_SIZE: return 15;
    default: return 1;
    }
}

RArchPlugin r_arch_plugin_x86_olly = {
    .meta = {
        .name = "x86.olly",
        .desc = "OllyDBG x86 disassembler",
        .author = "pancake, nibble",
        .version = R2_VERSION,
        .license = "GPL2",
        .status = R_PLUGIN_STATUS_OK,
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
    .data = &r_arch_plugin_x86_olly,
    .version = R2_VERSION
};
#endif
