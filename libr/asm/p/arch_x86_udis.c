/* radare2-extras: RArch plugin wrapping udis86 for x86 */

#include <r_lib.h>
#include <r_arch.h>
#include <r_asm.h>
#include <string.h>

#include "udis86/types.h"
#include "udis86/extern.h"

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
    ud_t d;
    ud_init(&d);

    /* set syntax based on session config */
    if (as && as->config) {
        switch (as->config->syntax) {
        case R_ARCH_SYNTAX_ATT:
            ud_set_syntax(&d, UD_SYN_ATT);
            break;
        default:
            ud_set_syntax(&d, UD_SYN_INTEL);
            break;
        }
        ud_set_mode(&d, as->config->bits);
    } else {
        ud_set_syntax(&d, UD_SYN_INTEL);
        ud_set_mode(&d, 32);
    }

    ud_set_input_buffer(&d, (uint8_t *)op->bytes, op->size);
    ud_set_pc(&d, op->addr);

    int opsize = ud_disassemble(&d);
    if (opsize < 1) {
        op->type = R_ANAL_OP_TYPE_ILL;
        op->size = 0;
        if (mask & R_ARCH_OP_MASK_DISASM) {
            op->mnemonic = strdup("invalid");
        }
        return false;
    }

    if (mask & R_ARCH_OP_MASK_DISASM) {
        const char *asmstr = ud_insn_asm(&d);
        if (!asmstr) {
            asmstr = "";
        }
        char *out = strdup(asmstr);
        if (as && as->config && as->config->syntax == R_ARCH_SYNTAX_JZ) {
            if (!strncmp(out, "je ", 3)) {
                memcpy(out, "jz", 2);
            } else if (!strncmp(out, "jne ", 4)) {
                memcpy(out, "jnz", 3);
            }
        }
        op->mnemonic = out;
    }

    op->size = opsize;
    return true;
}

static int info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_MINOP_SIZE:
        return 1;
    case R_ARCH_INFO_MAXOP_SIZE:
        return 15;
    default:
        return 1;
    }
}

RArchPlugin r_arch_plugin_x86_udis = {
    .meta = {
        .name = "x86.udis",
        .desc = "udis86 x86-16,32,64",
        .author = "pancake, nibble",
        .version = R2_VERSION,
        .license = "BSD",
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
    .data = &r_arch_plugin_x86_udis,
    .version = R2_VERSION
};
#endif

