#ifndef AGC_ASM_H
#define AGC_ASM_H

#include <r_types.h>

#define SWITCH_MASK 070000
#define LOWER_WIDE 07777
#define LOWER 01777
#define HIGHER 06000

typedef enum agc_insn_type {
	AGC_INSN_COM,
	AGC_INSN_DDOUBL,
	AGC_INSN_DOUBLE,
	AGC_INSN_DTCB,
	AGC_INSN_DTCF,
	AGC_INSN_EXTEND,
	AGC_INSN_INHINT,
	AGC_INSN_NOOP,
	AGC_INSN_OVSK,
	AGC_INSN_RELINT,
	AGC_INSN_RESUME,
	AGC_INSN_RETURN,
	AGC_INSN_TCAA,
	AGC_INSN_XLQ,
	AGC_INSN_XXALQ,
	AGC_INSN_ZL,
	AGC_INSN_TC,
	AGC_INSN_CCS,
	AGC_INSN_TCF,
	AGC_INSN_DAS,
	AGC_INSN_LXCH,
	AGC_INSN_INCR,
	AGC_INSN_ADS,
	AGC_INSN_CA,
	AGC_INSN_CS,
	AGC_INSN_INDEX,
	AGC_INSN_DXCH,
	AGC_INSN_TS,
	AGC_INSN_XCH,
	AGC_INSN_AD,
	AGC_INSN_MASK,
	AGC_INSN_DCOM,
	// a dirty hack so we can use the enum as indices of our lookup table.
	// this is due to the fact that the resume instruction is for some reason
	// present in both the 3-bit-opcode and 4-bit-opcode subsets of the
	// instruction set.
	AGC_INSN_RESUME2,
	AGC_INSN_SQUARE,
	AGC_INSN_ZQ,
	AGC_INSN_READ,
	AGC_INSN_WRITE,
	AGC_INSN_RAND,
	AGC_INSN_WAND,
	AGC_INSN_ROR,
	AGC_INSN_WOR,
	AGC_INSN_RXOR,
	AGC_INSN_EDRUPT,
	AGC_INSN_DV,
	AGC_INSN_BZF,
	AGC_INSN_MSU,
	AGC_INSN_QXCH,
	AGC_INSN_AUG,
	AGC_INSN_DIM,
	AGC_INSN_DCA,
	AGC_INSN_DCS,
	// same hack as above
	AGC_INSN_INDEX2,
	AGC_INSN_SU,
	AGC_INSN_BZMF,
	AGC_INSN_MP
} agc_insn_type;

// mnemonic lookup table
const char *agc_mnemonics[59];

// instruction representation
typedef struct agc_insn_t {
	agc_insn_type type;
	ut16 operand;
} agc_insn_t;

// actual disassembly logic
void disasm_agc_insn(
		agc_insn_t *op, unsigned int address, ut16 value, bool shift);

#endif
