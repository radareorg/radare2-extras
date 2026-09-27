#include <r_lib.h>
#include <r_arch.h>
#include <r_util.h>
#include "ppc/ppc_disasm/ppc_disasm.h"

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
    if (!op->bytes || op->size < 4) {
        return false;
    }
    ppc_word iaddr = (ppc_word)op->addr;
    ppc_word instr = R_ARCH_CONFIG_IS_BIG_ENDIAN(as->config)
        ? r_read_be32(op->bytes) : r_read_le32(op->bytes);
    char opcode[128] = {0};
    char operands[128] = {0};
    struct DisasmPara_PPC dp = {0};
    dp.opcode = opcode;
    dp.operands = operands;
    dp.iaddr = &iaddr;
    dp.instr = &instr;
    PPC_Disassemble(&dp, 1);
    op->size = 4;
    if (dp.type == PPCINSTR_BRANCH && !(instr & 2)) {
        char *target = strstr(operands, "0x");
        if (target) {
            snprintf(target, sizeof(operands) - (target - operands), "0x%x",
                (unsigned int)(ppc_word)(op->addr + dp.displacement));
        }
    }
    if (dp.flags & PPCF_ILLEGAL) {
        op->type = R_ANAL_OP_TYPE_ILL;
        return false;
    }
    if (mask & R_ARCH_OP_MASK_DISASM) {
        op->mnemonic = r_str_newf("%s%s%s", opcode, *operands ? " " : "", operands);
    }
    return true;
}

static int info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_MINOP_SIZE:
    case R_ARCH_INFO_MAXOP_SIZE:
    case R_ARCH_INFO_INVOP_SIZE:
    case R_ARCH_INFO_CODE_ALIGN:
        return 4;
    default:
        return -1;
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
    .endian = R_SYS_ENDIAN_BIG | R_SYS_ENDIAN_LITTLE,
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
