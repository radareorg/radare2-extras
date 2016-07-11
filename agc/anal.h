#ifndef AGC_ANAL_H
#define AGC_ANAL_H

#define SWITCH_MASK 070000
#define LOWER_WIDE 07777
#define LOWER 01777
#define HIGHER 06000

void analyze_agc_insn(RAnalOp *op, ut64 address, ut16 value, bool shift);

#endif
