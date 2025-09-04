#include <r_lib.h>
#include <r_arch.h>
#include <r_util.h>
#include "x86/bea/BeaEngine.h"

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
    DISASM dis = {0};
    dis.EIP = (long long)op->bytes;
    dis.VirtualAddr = op->addr;
    dis.Archi = ((as && as->config && as->config->bits == 64) ? 64 : 0);
    dis.SecurityBlock = op->size;
    if (as && as->config && as->config->syntax == R_ARCH_SYNTAX_ATT) {
        dis.Options = 0x400;
    }
    int sz = Disasm(&dis);
    op->size = (sz > 0)? sz: 0;
    if (mask & R_ARCH_OP_MASK_DISASM) {
        op->mnemonic = strdup(dis.CompleteInstr ? dis.CompleteInstr : "invalid");
    }
    return sz > 0;
}

static int info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_MINOP_SIZE: return 1;
    case R_ARCH_INFO_MAXOP_SIZE: return 15;
    default: return 1;
    }
}

RArchPlugin r_arch_plugin_x86_bea = {
    .meta = {
        .name = "x86.bea",
        .desc = "x86 BeaEngine disassembler",
        .author = "pancake, nibble",
        .version = R2_VERSION,
        .license = "LGPL",
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
    .data = &r_arch_plugin_x86_bea,
    .version = R2_VERSION
};
#endif
