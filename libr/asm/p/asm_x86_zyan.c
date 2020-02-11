/* radare - GPL3 - Copyright 2017 - mrexodia */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "x86/zyan/include/Zydis/Zydis.h"

static int disassemble(RAsm *a, RAsmOp *aop, const ut8 *buf, int len) {
	static ZydisInstructionDecoder decr;
	static ZydisInstructionInfo info;
	static ZydisInstructionFormatter fmtr;

	ZydisDecoderInitInstructionDecoder (&decr, a->bits);
	memset (&info, 0, sizeof (info));
	ZydisStatus st = ZydisDecoderDecodeInstruction (&decr, buf, len, a->pc, &info);
	if (ZYDIS_SUCCESS (st)) {
		ZydisFormatterInitInstructionFormatter (&fmtr, ZYDIS_FORMATTER_STYLE_INTEL);
		char str[128];
		str[0] = 0;
		ZydisFormatterFormatInstruction (&fmtr, &info, str, sizeof (str));
		r_strbuf_set (&aop->buf_asm, str);
	}

	return aop->size = info.length;
}

static RAsmPlugin r_asm_plugin_x86_zyan = {
	.name = "x86.zyan",
	.desc = "x86 Zyan Disassembler Engine plugin",
	.arch = "x86",
	.bits = 16 | 32 | 64,
	.disassemble = &disassemble,
	.license = "MIT"
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_zyan,
	.version = R2_VERSION
};
#endif
