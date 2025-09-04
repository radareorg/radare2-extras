#include <r_lib.h>
#include <r_arch.h>
#include <r_util.h>
#include "m68k/m68k_disasm/m68k_disasm.h"

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
    m68k_word bof[8] = {0};
    int iaddr = (int)op->addr;
    char opcode[256] = {0};
    char operands[256] = {0};
    const unsigned char *buf2;
    static struct DisasmPara_68k dp;
    int ilen;

    memcpy(bof, op->bytes, R_MIN(op->size, sizeof(bof)));
    dp.opcode = opcode;
    dp.operands = operands;
    dp.iaddr = (m68k_word *)(size_t)iaddr;
    dp.instr = bof;
    buf2 = (const ut8*)M68k_Disassemble(&dp);
    if (!buf2) {
        op->size = 2; // invalid, assume 2
        if (mask & R_ARCH_OP_MASK_DISASM) op->mnemonic = strdup("invalid");
        op->type = R_ANAL_OP_TYPE_ILL;
        return false;
    }
    ilen = (int)(buf2 - (const ut8*)bof);
    if (mask & R_ARCH_OP_MASK_DISASM) {
        char buf[512];
        if (*operands) snprintf(buf, sizeof(buf), "%s %s", opcode, operands);
        else snprintf(buf, sizeof(buf), "%s", opcode);
        r_str_replace_ch(buf, '#', 0, 1);
        op->mnemonic = strdup(buf);
    }
    op->size = ilen;
    return true;
}

static int info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_MINOP_SIZE: return 2;
    case R_ARCH_INFO_MAXOP_SIZE: return 10;
    default: return 2;
    }
}

RArchPlugin r_arch_plugin_m68k_net = {
    .meta = {
        .name = "m68k.net",
        .desc = "Motorola 68000",
        .author = "nibble",
        .version = R2_VERSION,
        .license = "BSD",
        .status = R_PLUGIN_STATUS_OK,
    },
    .arch = "m68k",
    .bits = R_SYS_BITS_PACK2(16, 32),
    .endian = R_SYS_ENDIAN_BIG,
    .info = &info,
    .decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ARCH,
    .data = &r_arch_plugin_m68k_net,
    .version = R2_VERSION
};
#endif
