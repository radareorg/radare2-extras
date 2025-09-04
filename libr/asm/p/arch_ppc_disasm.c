#include <r_lib.h>
#include <r_arch.h>
#include <r_util.h>
#include "ppc/ppc_disasm/ppc_disasm.h"

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
    ppc_word iaddr = (ppc_word)op->addr;
    ppc_word bof[4];
    char opcode[128] = {0};
    char operands[128] = {0};
    struct DisasmPara_PPC dp = {0};
    memcpy(bof, op->bytes, R_MIN(op->size, sizeof(bof)));
    dp.opcode = opcode;
    dp.operands = operands;
    dp.iaddr = &iaddr;
    dp.instr = bof;
    PPC_Disassemble(&dp, as && as->config ? as->config->big_endian : 0);
    if (mask & R_ARCH_OP_MASK_DISASM) {
        char res[256];
        snprintf(res, sizeof(res), "%s %s", opcode, operands);
        op->mnemonic = strdup(res);
    }
    op->size = 4;
    return true;
}

static int info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_MINOP_SIZE: return 4;
    case R_ARCH_INFO_MAXOP_SIZE: return 4;
    default: return 4;
    }
}

RArchPlugin r_arch_plugin_ppc_disasm = {
    .meta = {
        .name = "ppc.disasm",
        .desc = "Tiny PowerPC disassembly",
        .author = "pancake, nibble",
        .version = R2_VERSION,
        .license = "GPL3",
        .status = R_PLUGIN_STATUS_OK,
    },
    .arch = "ppc",
    .bits = R_SYS_BITS_PACK1(32),
    .endian = R_SYS_ENDIAN_BIG,
    .info = &info,
    .decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ARCH,
    .data = &r_arch_plugin_ppc_disasm,
    .version = R2_VERSION
};
#endif
