/* radare2 - LGPL-3.0-only - Copyright 2026 - n0p */
/* uSIP (MD32 family, VLIW packet variant) packet decoder.
 *
 * The unit is the 16-bit big-endian halfword.  A packet is the run of units up to and including the first one with
 * bit 15 set (at most 8 units).  Inside a packet every instruction is a head (bit 15 = 0) plus 0, 1 or 2 tails that are
 * not necessarily adjacent to it: the packet is a sequence of groups, each laid out heads first and then the tails
 * dealt round-robin among the heads that take tails.  No bit selects the layout, so the decoder enumerates every
 * group split and head/tail assignment allowed by the form table (usip_opcodes.h) and keeps the reading with the
 * fewest unknown units, then the fewest instructions, then the fewest groups, then the documented tie-break
 * penalties.  Only slot 0 (the first unit) can hold control flow and, when the control instruction does not close
 * the packet, the rest of the packet is its delay slot.  See README.md "uSIP mode". */

#ifndef USIP_DECODE_H
#define USIP_DECODE_H

#include <r_types.h>
#include <r_util.h>

#define USIP_MAX_UNITS 8
#define USIP_MAX_VALS 8

typedef struct usip_opcode_t UsipOpcode;

enum usip_pseudo {
	USIP_P_FORM = 0,   /* a table form (UsipInsn.op) */
	USIP_P_HWORD,      /* 16-bit unit without a reading */
	USIP_P_WORD,       /* head + tail without a reading */
	USIP_P_WORD_CTRL,  /* control-flow form whose tail is too far away (not control flow) */
	USIP_P_W48,        /* head + hi + lo without a reading */
	USIP_P_LO,         /* context rule lo_after_hi */
	USIP_P_EXT,        /* context rule ext_after_ldst */
	USIP_P_BE79,       /* context rule be79_prefix (2 units) */
};

typedef struct {
	ut8 head;               /* unit index of the head */
	ut8 ntails;             /* 0, 1 or 2 */
	ut8 tails[2];           /* unit indices of the tails (hi, lo) */
	ut8 pseudo;             /* enum usip_pseudo */
	const UsipOpcode *op;   /* NULL when pseudo != USIP_P_FORM */
	ut8 kind;               /* enum usip_kind (USIP_K_OTHER / USIP_K_FMT for the pseudo forms) */
	const char *mnem;       /* mnemonic */
	ut64 w;                 /* the units concatenated big-endian (head first) */
	bool has_target;
	ut64 target;            /* branch/call/loop-end target */
	ut8 nvals;              /* decoded field values (op->fields order) */
	st64 vals[USIP_MAX_VALS];
} UsipInsn;

typedef struct {
	ut64 addr;                      /* address of the first unit */
	ut8 nunits;
	ut16 units[USIP_MAX_UNITS];
	ut8 ninsn;
	UsipInsn insn[USIP_MAX_UNITS];  /* sorted by head unit */
	ut8 owner[USIP_MAX_UNITS];      /* instruction index owning each unit */
	bool ambiguous;                 /* several readings with the same score */
	bool truncated;                 /* the buffer ended before the close bit */
	bool delay;                     /* slot 0 is control flow and the rest of the packet is its delay slot */
} UsipPacket;

/* Collect the units of the packet that starts at buf (len bytes available).  Returns the number of units (0 when
 * len < 2) and sets *truncated when the close bit was not reached. */
int usip_scan_units(const ut8 *buf, int len, ut16 *units, bool *truncated);

/* Decode a whole packet (n units, 1..USIP_MAX_UNITS) starting at addr. */
void usip_decode_packet(UsipPacket *pk, ut64 addr, const ut16 *units, int n, bool truncated);

/* Mnemonic and operands of instruction i of the packet. */
void usip_insn_text(const UsipPacket *pk, int i, RStrBuf *sb);

/* Address of a unit / of the head of an instruction. */
static inline ut64 usip_unit_addr(const UsipPacket *pk, int unit) {
	return pk->addr + 2 * (ut64)unit;
}

/* Table accessors (the table itself lives in usip_decode.c). */
const char *usip_kind_name(int kind);
const char *usip_conf_name(int conf);
int usip_op_index(const UsipOpcode *op);
const char *usip_op_form(const UsipOpcode *op);
int usip_op_kind(const UsipOpcode *op);
int usip_op_conf(const UsipOpcode *op);
unsigned usip_op_flags(const UsipOpcode *op);
int usip_op_nargs(const UsipOpcode *op);
const char *usip_op_field_name(const UsipOpcode *op, int i);
int usip_op_field_type(const UsipOpcode *op, int i);

#endif
