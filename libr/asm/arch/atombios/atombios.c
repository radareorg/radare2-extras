/* radare - LGPL - Copyright 2018 damo22 */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_endian.h>
#include "atombios.h"

// FIXME: Globals ugh
static int last_reg_index  = INDEX_NONE;
static int last_reg_offset = 0;
static int opt_reg_addresses = 0;

const char *align_source_esil[] = {
	"",
	"_01",
	"_12",
	"_23",
	"_0",
	"_1",
	"_2",
	"_3"
};

const char *align_byte_esil[] = { "_0", "_1", "_2", "_3" };
const char *align_word_esil[] = { "_01", "_12", "_23", "" };
const char *align_long_esil[] = { "", "", "", "" };

const char *addrtypes_esil[] = {
	"0x%04x,r", "p%d", "w%d", "0x%02x,f", "0x%04x,dt", "0x%04x,D_IDunimpl",
	"0x%04x,pll", "0x%04x,mc",
	"0x%02x", "0x%04x", "0x%08x"
};

const char *align_source[] = {
	"XXXX",
	"..XX",
	".XX.",
	"XX..",
	"...X",
	"..X.",
	".X..",
	"X..."
};

const char *align_byte[] = { "...X", "..X.", ".X..", "X..." };
const char *align_word[] = { "..XX", ".XX.", "XX..", "?..?" };
const char *align_long[] = { "XXXX", "????", "????", "????" };

const int   size_align[] = { 4, 2, 2, 2, 1, 1, 1, 1 };

const char *addrnames[] = { "REG", "PS", "WS", "FB", "ID", "IM", "PLL", "MC", "dec", "hex8", "hex16", "null" };

const char *addrtypes[] = {
	"REG[0x%04x]", "PARAM[%d]", "WORK[%d]", "FB[0x%02x]", "DATA[0x%04x]", "0x%04x,<!impl>",
	"PLL[0x%04x]", "MC[0x%04x]",
	"0x%02x", "0x%04x", "0x%08x"
};

int addrtypes_shift[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

const char *addrtypes_im[] = { NULL, "0x%02x", "0x%04x", NULL, "0x%08x" };

const char *index_command_table[] = {
	"ASIC_Init", "GetDisplaySurfaceSize", "ASIC_RegistersInit",
	"VRAM_BlockVenderDetection", "SetClocksRatio_DIGxEncoderControl", "MemoryControllerInit",
	"EnableCRTCMemReq", "MemoryParamAdjust", "DVOEncoderControl",
	"GPIOPinControl", "SetEngineClock", "SetMemoryClock",
	"SetPixelClock", "DynamicClockGating", "ResetMemoryDLL",
	"ResetMemoryDevice", "MemoryPLLInit", "AdjustDisplayPll",
	"AdjustMemoryController", "EnableASIC_StaticPwrMgt", "ASIC_StaticPwrMgtStatusChange_SetUniphyInstance",
	"DAC_LoadDetection", "LVTMAEncoderControl", "LCD1OutputControl",
	"DAC1EncoderControl", "DAC2EncoderControl", "DVOOutputControl",
	"CV1OutputControl", "GetConditionalGoldenSetting_SetCRTC_DPM_State", "TVEncoderControl",
	"TMDSAEncoderControl", "LVDSEncoderControl", "TV1OutputControl",
	"EnableScaler", "BlankCRTC", "EnableCRTC",
	"GetPixelClock", "EnableVGA_Render", "EnableVGA_Access_GetSCLKOverMCLKRatio",
	"SetCRTC_Timing", "SetCRTC_OverScan", "SetCRTC_Replication",
	"SelectCRTC_Source", "EnableGraphSurfaces", "UpdateCRTC_DoubleBufferRegisters",
	"LUT_AutoFill", "EnableHW_IconCursor", "GetMemoryClock",
	"GetEngineClock", "SetCRTC_UsingDTDTiming", "ExternalEncoderControl",
	"LVTMAOutputControl", "VRAM_BlockDetectionByStrap", "MemoryCleanUp",
	"ReadEDIDFromHWAssistedI2C_ProcessI2cChannelTransaction",
	"WriteOneByteToHWAssistedI2C", "ReadHWAssistedI2CStatus_HPDInterruptService",
	"SpeedFanControl", "PowerConnectorDetection", "MC_Synchronization",
	"ComputeMemoryEnginePLL", "MemoryRefreshConversion", "VRAM_GetCurrentInfoBlock",
	"DynamicMemorySettings", "MemoryTraining", "EnableSpreadSpectrumOnPPLL",
	"TMDSAOutputControl", "SetVoltage", "DAC1OutputControl",
	"DAC2OutputControl", "SetupHWAssistedI2CStatus", "ClockSource",
	"MemoryDeviceInit", "EnableYUV", "DIG1EncoderControl",
	"DIG2EncoderControl", "DIG1TransmitterControl_UNIPHYTransmitterControl",
	"DIG2TransmitterControl_LVTMATransmitterControl",
	"ProcessAuxChannelTransaction", "DPEncoderService"
};

const char *index_data_table[] = {
	"UtilityPipeLine", "MultimediaCapabilityInfo", "MultimediaConfigInfo",
	"StandardVESA_Timing", "FirmwareInfo", "DAC_Info",
	"LVDS_Info", "TMDS_Info", "AnalogTV_Info",
	"SupportedDevicesInfo", "GPIO_I2C_Info", "VRAM_UsageByFirmware",
	"GPIO_Pin_LUT", "VESA_ToInternalModeLUT", "ComponentVideoInfo",
	"PowerPlayInfo", "CompassionateData", "SaveRestoreInfo_DispDevicePriorityInfo",
	"PPLL_SS_Info_SS_Info", "OemInfo", "XTMDS_Info",
	"MclkSS_Info", "Object_Info_Object_Header", "IndirectIOAccess",
	"MC_InitParameter_AdjustARB_SEQ", "ASIC_VDDC_Info", "ASIC_InternalSS_Info_ASIC_MVDDC_Info",
	"TV_VideoMode_DispOutInfo", "VRAM_Info", "MemoryTrainingInfo_ASIC_MVDDQ_Info",
	"IntegratedSystemInfo", "ASIC_ProfilingInfo_ASIC_VDDCI_Info",
	"VoltageObjectInfo_VRAM_GPIO_DetectionInfo",
	"PowerSourceInfo"
};

const char *index_ati_port[] = {
	"INDIRECT_IO_MM",
	"INDIRECT_IO_PLL",
	"INDIRECT_IO_MC",
	"INDIRECT_IO_PCIE",
};

const char *index_work_reg[] = {
	[WS_QUOTIENT]   = "w0",
	[WS_REMAINDER]  = "w1",
	[WS_DATAPTR]    = "w2",
	[WS_SHIFT]      = "w3",
	[WS_OR_MASK]    = "w4",
	[WS_AND_MASK]   = "w5",
	[WS_FB_WINDOW]  = "w6",
	[WS_ATTRIBUTES] = "w7",
	[WS_REGPTR]     = "w8"
};

#define TABENTRY(x) { #x, (index_ ## x), sizeof (index_ ## x) / sizeof (const char **) }

index_table_t index_tables[INDEXTABLE_SIZEOF] = {
	{ NULL, NULL, 0 },
	TABENTRY (command_table),
	TABENTRY (data_table),
	TABENTRY (ati_port),
	TABENTRY (work_reg),
	{ "REG_MM",   NULL, 0 },
	{ "REG_PLL",  NULL, 0 },
	{ "REG_MC",   NULL, 0 },
	{ "REG_PCIE", NULL, 0 },
	{ "REG_PCICONFIG", NULL, 0 },
	{ "REG_SYSTEMIO", NULL, 0 }
};

const char *get_index (int type, int val)
{
	if (type < 0 || val < 0 ||
			type >= sizeof (index_tables) / sizeof (const struct index_table_s))
		return NULL;
	if (! index_tables[type].tab || val >= index_tables[type].len)
		return NULL;
	return index_tables[type].tab[val];
}

static int op_ds      (const ut8 *, char *);
static int op_sdb     (const ut8 *, char *);
static int op_0x      (const ut8 *, char *);
static int op_1x8     (const ut8 *, char *);
static int op_1x16    (const ut8 *, char *);
static int op_src     (const ut8 *, char *);
static int op_dest    (const ut8 *, char *);
static int op_destsrc (const ut8 *, char *);
static int op_shift   (const ut8 *, char *);
static int op_switch  (const ut8 *, char *);
static int op_mask    (const ut8 *, char *);
static int op_setpt0  (const ut8 *, char *);
static int op_setpt1  (const ut8 *, char *);
static int op_setrb   (const ut8 *, char *);

const optab_t optable[256] = {
	{ NULL, NULL, NULL, D_null, 0, 0 },
	{ op_destsrc, "move", "=", D_REG, 0, 0 },
	{ op_destsrc, "move", "=", D_PS, 0, 0 },
	{ op_destsrc, "move", "=", D_WS, 0, 0 },
	{ op_destsrc, "move", "=", D_FB, 0, 0 },
	{ op_destsrc, "move", "=", D_PLL, 0, 0 },
	{ op_destsrc, "move", "=", D_MC, 0, 0 },
	{ op_destsrc, "and", "&=", D_REG, 0, 0 },
	{ op_destsrc, "and", "&=", D_PS, 0, 0 },
	{ op_destsrc, "and", "&=", D_WS, 0, 0 },
	{ op_destsrc, "and", "&=", D_FB, 0, 0 },
	{ op_destsrc, "and", "&=", D_PLL, 0, 0 },
	{ op_destsrc, "and", "&=", D_MC, 0, 0 },
	{ op_destsrc, "or", "|=", D_REG, 0, 0 },
	{ op_destsrc, "or", "|=", D_PS, 0, 0 },
	{ op_destsrc, "or", "|=", D_WS, 0, 0 },
	{ op_destsrc, "or", "|=", D_FB, 0, 0 },
	{ op_destsrc, "or", "|=", D_PLL, 0, 0 },
	{ op_destsrc, "or", "|=", D_MC, 0, 0 },
	{ op_shift,   "shiftl", "<<=", D_REG, 0, 0 },
	{ op_shift,   "shiftl", "<<=", D_PS, 0, 0 },
	{ op_shift,   "shiftl", "<<=", D_WS, 0, 0 },
	{ op_shift,   "shiftl", "<<=", D_FB, 0, 0 },
	{ op_shift,   "shiftl", "<<=", D_PLL, 0, 0 },
	{ op_shift,   "shiftl", "<<=", D_MC, 0, 0 },
	{ op_shift,   "shiftr", ">>=", D_REG, 0, 0 },
	{ op_shift,   "shiftr", ">>=", D_PS, 0, 0 },
	{ op_shift,   "shiftr", ">>=", D_WS, 0, 0 },
	{ op_shift,   "shiftr", ">>=", D_FB, 0, 0 },
	{ op_shift,   "shiftr", ">>=", D_PLL, 0, 0 },
	{ op_shift,   "shiftr", ">>=", D_MC, 0, 0 },
	{ op_destsrc, "mul", "*=", D_REG, 0, 0 },
	{ op_destsrc, "mul", "*=", D_PS, 0, 0 },
	{ op_destsrc, "mul", "*=", D_WS, 0, 0 },
	{ op_destsrc, "mul", "*=", D_FB, 0, 0 },
	{ op_destsrc, "mul", "*=", D_PLL, 0, 0 },
	{ op_destsrc, "mul", "*=", D_MC, 0, 0 },
	{ op_destsrc, "div", "/=", D_REG, 0, 0 },
	{ op_destsrc, "div", "/=", D_PS, 0, 0 },
	{ op_destsrc, "div", "/=", D_WS, 0, 0 },
	{ op_destsrc, "div", "/=", D_FB, 0, 0 },
	{ op_destsrc, "div", "/=", D_PLL, 0, 0 },
	{ op_destsrc, "div", "/=", D_MC, 0, 0 },
	{ op_destsrc, "add", "+=", D_REG, 0, 0 },
	{ op_destsrc, "add", "+=", D_PS, 0, 0 },
	{ op_destsrc, "add", "+=", D_WS, 0, 0 },
	{ op_destsrc, "add", "+=", D_FB, 0, 0 },
	{ op_destsrc, "add", "+=", D_PLL, 0, 0 },
	{ op_destsrc, "add", "+=", D_MC, 0, 0 },
	{ op_destsrc, "sub", "-=", D_REG, 0, 0 },
	{ op_destsrc, "sub", "-=", D_PS, 0, 0 },
	{ op_destsrc, "sub", "-=", D_WS, 0, 0 },
	{ op_destsrc, "sub", "-=", D_FB, 0, 0 },
	{ op_destsrc, "sub", "-=", D_PLL, 0, 0 },
	{ op_destsrc, "sub", "-=", D_MC, 0, 0 },
	{ op_setpt1,  "set_ati_port", NULL, D_hex16, INDEX_REG_MM, INDEX_ATI_PORT },
	{ op_setpt0,  "set_pci_port", NULL, D_null, INDEX_REG_PCICONFIG, 0 },
	{ op_setpt0,  "set_systemio_port", NULL, D_null, INDEX_REG_SYSTEMIO, 0 },
	{ op_setrb,   "set_reg_block", NULL, D_hex16, 0, 0 },
	{ op_src,     "set_fb_base", NULL, D_hex16, 0, 0 },
	{ op_destsrc, "cmp", "==", D_REG, 0, 0 },
	{ op_destsrc, "cmp", "==", D_PS, 0, 0 },
	{ op_destsrc, "cmp", "==", D_WS, 0, 0 },
	{ op_destsrc, "cmp", "==", D_FB, 0, 0 },
	{ op_destsrc, "cmp", "==", D_PLL, 0, 0 },
	{ op_destsrc, "cmp", "==", D_MC, 0, 0 },
	{ op_switch,  "switch", NULL, D_hex16, 0, 0 },
	{ op_1x16,    "jmp", NULL, D_hex16, 0, 0 },
	{ op_1x16,    "je ", "==", D_hex16, 0, 0 },
	{ op_1x16,    "jl ", "<", D_hex16, 0, 0 },
	{ op_1x16,    "jg ", ">", D_hex16, 0, 0 },
	{ op_1x16,    "jle", "<=", D_hex16, 0, 0 },
	{ op_1x16,    "jge", ">=", D_hex16, 0, 0 },
	{ op_1x16,    "jne", "!=", D_hex16, 0, 0 },
	{ op_destsrc, "bitest", "&", D_REG, 0, 0 },
	{ op_destsrc, "bitest", "&", D_PS, 0, 0 },
	{ op_destsrc, "bitest", "&", D_WS, 0, 0 },
	{ op_destsrc, "bitest", "&", D_FB, 0, 0 },
	{ op_destsrc, "bitest", "&", D_PLL, 0, 0 },
	{ op_destsrc, "bitest", "&", D_MC, 0, 0 },
	{ op_1x8,     "mdelay", NULL, D_hex8, 0, 0 },
	{ op_1x8,     "udelay", NULL, D_hex8, 0, 0 },
	{ op_1x8,     "call", NULL, D_hex8, 0, INDEX_COMMAND_TABLE },
	{ op_1x8,     "<deprecated> repeat", NULL, D_hex8, 0, 0 },
	{ op_dest,    "clear", "0", D_REG, 0, 0 },
	{ op_dest,    "clear", "0", D_PS, 0, 0 },
	{ op_dest,    "clear", "0", D_WS, 0, 0 },
	{ op_dest,    "clear", "0", D_FB, 0, 0 },
	{ op_dest,    "clear", "0", D_PLL, 0, 0 },
	{ op_dest,    "clear", "0", D_MC, 0, 0 },
	{ op_0x,      "nop", NULL, D_null, 0, 0 },
	{ op_0x,      "ret", NULL, D_null, 0, 0 },
	{ op_mask,    "mask", NULL, D_REG, 0, 0 },
	{ op_mask,    "mask", NULL, D_PS, 0, 0 },
	{ op_mask,    "mask", NULL, D_WS, 0, 0 },
	{ op_mask,    "mask", NULL, D_FB, 0, 0 },
	{ op_mask,    "mask", NULL, D_PLL, 0, 0 },
	{ op_mask,    "mask", NULL, D_MC, 0, 0 },
	{ op_1x8,     "post_card", NULL, D_hex8, 0, 0 },
	{ op_1x8,     "<!impl> beep", NULL, D_hex8, 0, 0 },
	{ op_0x,      "<deprecated> save_reg", NULL, D_null, 0, 0 },
	{ op_0x,      "<deprecated> restore_reg", NULL, D_null, 0, 0 },
	{ op_sdb,     "set_data_block", NULL, D_hex8, 0, INDEX_DATA_TABLE },
	{ op_destsrc, "xor", "^=", D_REG, 0, 0 },
	{ op_destsrc, "xor", "^=", D_PS, 0, 0 },
	{ op_destsrc, "xor", "^=", D_WS, 0, 0 },
	{ op_destsrc, "xor", "^=", D_FB, 0, 0 },
	{ op_destsrc, "xor", "^=", D_PLL, 0, 0 },
	{ op_destsrc, "xor", "^=", D_MC, 0, 0 },
	{ op_destsrc, "shl", "<<=", D_REG, 0, 0 },
	{ op_destsrc, "shl", "<<=", D_PS, 0, 0 },
	{ op_destsrc, "shl", "<<=", D_WS, 0, 0 },
	{ op_destsrc, "shl", "<<=", D_FB, 0, 0 },
	{ op_destsrc, "shl", "<<=", D_PLL, 0, 0 },
	{ op_destsrc, "shl", "<<=", D_MC, 0, 0 },
	{ op_destsrc, "shr", ">>=", D_REG, 0, 0 },
	{ op_destsrc, "shr", ">>=", D_PS, 0, 0 },
	{ op_destsrc, "shr", ">>=", D_WS, 0, 0 },
	{ op_destsrc, "shr", ">>=", D_FB, 0, 0 },
	{ op_destsrc, "shr", ">>=", D_PLL, 0, 0 },
	{ op_destsrc, "shr", ">>=", D_MC, 0, 0 },
	{ op_0x,      "<!doc> debug", NULL, D_null, 0, 0 },
	{ op_ds,      "bindata", NULL, D_null, 0, 0 },
	[0x80] = { op_0x, "<!impl> extended", NULL, D_null, 0, 0 },
	[0xff] = { op_0x, "<reserved>", NULL, D_null, 0, 0 }
};

int get_table_offset(ut16 *table, int idx) {
	int i, last = 0, offset = 0;
	static int wrapwarning = 0;

	if (! table || ! table[idx])
		return 0;

	for (i = 0; i <= idx; i++) {
		int off = table[i];
		if (off) {
			if (off < last)
				offset += 0x10000;
			last = off - 0x8000;
		}
	}

	if (offset && ! wrapwarning++)
		printf ("*** Wrap around of table offset - assuming offset\n");
	return table[idx] + offset;
}

int sub_dest (const ut8 *d, char *out, int type, int align, int size, int index) {
	ut32    val;
	int         r;
	const char *ind;
	switch (type) {
		case D_REG:
			val  = *((ut16 *) d);
			r    = 2;
			break;
		case D_ID:  case D_IM:
			out += sprintf (out, "<internal - illegal addrtype %s>", addrnames [type]);
			val  = 0;
			r    = 0;
			break;
		default:
			val = *d;
			r   = 1;
	}
	if (type == D_WS && (ind = get_index (INDEX_WORK_REG, val)) )
		out += sprintf (out, "%s", ind);
	else if (r)
		out += sprintf (out, addrtypes [type], val << addrtypes_shift[type]);
	switch (size) {
		case 1:
			out += sprintf (out, " [%s]", align_byte[align]);
			break;
		case 2:
			out += sprintf (out, " [%s]", align_word[align]);
			break;
		case 4:
			out += sprintf (out, " [%s]", align_long[align]);
			break;
	}
	if (type == D_REG && (ind = get_index (last_reg_index, val+last_reg_offset)) )
		out += sprintf (out, " (%s)", ind);
	if (r && (ind = get_index (index, val)) )
		out += sprintf (out, " (%s)", ind);
	return r;
}
int sub_src (const ut8 *d, char *out, int type, int align, int size, int index) {
	ut32    val;
	int         r;
	const char *ind;
	switch (type) {
		case D_IM:
			r = size;
			break;
		case D_PS:  case D_WS:  case D_FB:  case D_PLL:  case D_MC:
			r = 1;
			break;
		case D_REG:  case D_ID:
			r = 2;
	}
	switch (r) {
		case 1:
			val = *d;
			break;
		case 2:
			val = r_read_le16(d);
			break;
		case 4:
			val = r_read_le32(d);
			break;
	}
	if (type == D_IM) {
		out += sprintf (out, addrtypes_im [size], val);
	} else if (type == D_WS && (ind = get_index (INDEX_WORK_REG, val)) ) {
		out += sprintf (out, "%s", ind);
		out += sprintf (out, " [%s]", align_source[align]);
	} else {
		out += sprintf (out, addrtypes [type], val << addrtypes_shift [type]);
		out += sprintf (out, " [%s]", align_source[align]);
	}
	if (type == D_REG && (ind = get_index (last_reg_index, val+last_reg_offset)) )
		out += sprintf (out, " (%s)", ind);
	if ( (ind = get_index (index, val)) )
		out += sprintf (out, " (%s)", ind);
	return r;
}

int op_ds (const ut8 *d, char *out) {
	const optab_t *op = &optable[d[0]];
	ut16 size = r_read_at_le16(d, 1);
	out += sprintf (out, "%-5s  %d bytes", op->name, size + 2);
	return size + 3;
}

int op_sdb (const ut8 *d, char *out) {
	const optab_t *op = &optable[d[0]];
	const char    *ind;
	out += sprintf (out, "%-5s  ", op->name);
	out += sprintf (out, addrtypes [op->desttype],
			d[1] << addrtypes_shift [op->desttype]);
	if (d[1] == 0xff)
		out += sprintf (out, "  (this table)");
	else if ( (ind = get_index (op->destindex, d[1])) )
		out += sprintf (out, "  (%s)", ind);
	return 2;
}

int op_0x (const ut8 *d, char *out) {
	const optab_t *op = &optable[d[0]];
	strcpy (out, op->name);
	return 1;
}
int op_1x8 (const ut8 *d, char *out) {
	const optab_t *op = &optable[d[0]];
	const char    *ind;
	out += sprintf (out, "%-5s  ", op->name);
	out += sprintf (out, addrtypes [op->desttype],
			d[1] << addrtypes_shift [op->desttype]);
	if ( (ind = get_index (op->destindex, d[1])) )
		out += sprintf (out, "  (%s)", ind);
	return 2;
}
int op_1x16 (const ut8 *d, char *out) {
	const optab_t *op = &optable[d[0]];
	const char    *ind;
	out += sprintf (out, "%-5s  ", op->name);
	out += sprintf (out, addrtypes [op->desttype],
			r_read_at_le16(d, 1) << addrtypes_shift [op->desttype]);
	if ( (ind = get_index (op->destindex, d[1])) )
		out += sprintf (out, "  (%s)", ind);
	return 3;
}

int op_src (const ut8 *d, char *out) {
	const optab_t *op = &optable[d[0]];
	ut8       *t    = (ut8 *)&d[1];
	int            attr = *t++;
	out += sprintf (out, "%-5s  ", op->name);
	t   += sub_src (t, out, attr & 0x07, (attr & 0x38) >> 3, size_align[(attr & 0x38)>>3], op->srcindex);
	return t - d;
}

int op_dest (const ut8 *d, char *out) {
	const optab_t *op = &optable[d[0]];
	ut8 *t    = (ut8 *)&d[1];
	int      attr = *t++;
	out += sprintf  (out, "%-5s  ", op->name);
	t   += sub_src (t, out, op->desttype, (attr & 0x38) >> 3, size_align[(attr & 0x38)>>3], op->destindex);
	return t - d;
}

int op_destsrc (const ut8 *d, char *out) {
	const optab_t *op = &optable[d[0]];
	ut8 *t    = (ut8 *)&d[1];
	int      attr = *t++;
	out += sprintf  (out, "%-5s  ", op->name);
	t   += sub_dest (t, out, op->desttype, attr >> 6, size_align[(attr & 0x38)>>3], op->destindex);
	out += strlen   (out);
	out += sprintf  (out, " <- ");
	t   += sub_src  (t, out, attr & 0x07, (attr & 0x38) >> 3, size_align[(attr & 0x38)>>3], op->srcindex);
	return t - d;
}

int op_shift (const ut8 *d, char *out) {
	const optab_t *op = &optable[d[0]];
	ut8 *t    = (ut8 *)&d[1];
	int      attr = *t++;
	out += sprintf  (out, "%-5s  ", op->name);
	t   += sub_src (t, out, op->desttype, (attr & 0x38) >> 3, size_align[(attr & 0x38)>>3], op->destindex);
	out += strlen   (out);
	out += sprintf  (out, " by %02x", *t++);
	return t - d;
}

int op_switch (const ut8 *d, char *out) {
	const optab_t *op = &optable[d[0]];
	ut8 *t = (ut8 *)&d[1];
	int attr = *t++;
	out += sprintf (out, "%-5s  ", op->name);
	t   += sub_src (t, out, attr & 0x07, (attr & 0x38) >> 3, size_align[(attr & 0x38)>>3], op->srcindex);
	out += strlen  (out);

	while (t[0] != 0x5a && t[1] != 0x5a) { /* EndOfSwitch: 2x NOP */
		if (*t++ != 'c') {
			out += sprintf (out, " (missing CASE for switch)");
			t   -= 3;
			break;
		}
		switch (size_align[(attr & 0x38)>>3]) {
			case 1:
				out += sprintf (out, " %02x ->", *t++);
				break;
			case 2:
				out += sprintf (out, " %04x ->", r_read_le16(t));
				t   += 2;
				break;
			case 4:
				out += sprintf (out, " %08x ->", r_read_le32(t));
				t   += 4;
				break;
		}
		out += sprintf (out, " %04x", r_read_le16(t));
		t   += 2;
	}
	t += 2;
	return t - d;
}
int op_mask (const ut8 *d, char *out) {
	const optab_t *op = &optable[d[0]];
	ut8 *t    = (ut8 *)&d[1];
	int      attr = *t++;
	out += sprintf  (out, "%-5s  ", op->name);
	t   += sub_dest (t, out, op->desttype, attr >> 6, size_align[(attr & 0x38)>>3], op->destindex);
	out += strlen   (out);
	out += sprintf  (out, " & ");
	t   += sub_src  (t, out, D_IM, (attr & 0x38) >> 3, size_align[(attr & 0x38)>>3], 0);
	out += strlen   (out);
	out += sprintf  (out, " | ");
	t   += sub_src  (t, out, attr & 0x07, (attr & 0x38) >> 3, size_align[(attr & 0x38)>>3], 0);
	return t - d;
}
int op_setpt0 (const ut8 *d, char *out) {
	const optab_t *op = &optable[d[0]];
	last_reg_index = op->srcindex;
	/* is never INDEX_REG_MM */
	addrtypes_shift[D_REG] = 0;
	return op_0x (d, out);
}
int op_setpt1 (const ut8 *d, char *out) {
	const optab_t *op = &optable[d[0]];
	last_reg_index = op->srcindex + r_read_at_le16(d, 1);
	if (last_reg_index == INDEX_REG_MM && opt_reg_addresses)
		addrtypes_shift[D_REG] = 2;
	else
		addrtypes_shift[D_REG] = 0;
	return op_1x16 (d, out);
}
int op_setrb (const ut8 *d, char *out) {
	const optab_t *op = &optable[d[0]];
	last_reg_offset = op->srcindex + r_read_at_le16(d, 1);
	return op_1x16 (d, out);
}

/*
   void do_data (const ut8 *data, int off, int nr)
   {
   int len;
   const char *comment = NULL;
   int frev = data[off+2];
   int crev = data[off+3];
   data_dumper_t *dt = get_data_dumper (nr, &frev, &crev, &comment);

   if (! dt)
   return;
   if (frev == 0)
   fprintf (stdout, "  NOTE: General revisionless dumper only.\n");
   else if (frev != data[off+2] || crev != data[off+3])
   fprintf (stdout, "  NOTE: Dumper revision differs.   "
   "Used:   Format Rev. %02x  Content Rev. %02x\n", frev, crev);
   if (comment)
   fprintf (stdout, "  NOTE: %s\n", comment);
   if (frev == 0 || frev != data[off+2] || crev != data[off+3] || comment)
   fputs ("\n", stdout);
   len = (*dt) (data+off, data+off, 1);
   fprintf (stdout, "\n  Total data structure size:  %04x\n\n", len);
   }
 */ 

int atombios_inst_len(const ut8 *buf) {
	const ut8 *d = buf;
	char tmpbuf[1024] = {0}; // can have data table with hugeass instruction
	ut8 size = 0;

	if (optable[*d].process) {
		size = optable[*d].process (d, tmpbuf);
	} else {
		size = 1;
	}
	return size;
}

int atombios_disassemble(const ut8 *inbuf, int len, char *outbuf) {
	const ut8 *d = inbuf;
	ut8 size = 0;

	if (optable[*d].process) {
		size = optable[*d].process (d, outbuf);
		if (size > len) {
			sprintf (outbuf, "<truncated>");
			size = 1;
		}
	} else {
		sprintf (outbuf, "<unknown opcode> %02x", *d);
		size = 1;
	}
	return size;
}
