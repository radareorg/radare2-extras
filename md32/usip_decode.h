/* radare2 - LGPL-3.0-only - Copyright 2026 - n0p */
/* uSIP (MD32 family, VLIW packet variant) packet decoder.
 *
 * The unit is the 16-bit big-endian halfword.  A packet is the run of units up to and including the first one with
 * bit 15 set (at most 8 units).  Inside a packet every instruction is a head (bit 15 = 0) plus 0, 1 or 2 tails that are
 * not necessarily adjacent to it: the packet is a sequence of groups, each laid out heads first and then the tails
 * dealt round-robin among the heads that take tails.  No bit selects the layout, so the decoder enumerates every
 * group split and head/tail assignment allowed by the form table (usip_opcodes.h), adds the explicit candidates of
 * the packet grammar and keeps the smallest reading in the prior-free total order (s0, I, Fv, -A, K): unknown units
 * plus the documented tie-break penalties, then the number of instructions, then the tails whose adjacency
 * contradicts the F pattern, then (minus) the adjacent tails, then the lexicographic key of the assignment.  The
 * 48/64-bit b<cond>.l prefix forms are matched on the first units of the packet before the layout.  Only slot 0 (the
 * first unit) can hold control flow and, when the control instruction does not close the packet, the rest of the
 * packet is its delay slot.  Some control forms carry a target guard (the target must be a packet start of the same
 * function or a function start): the caller supplies that knowledge through UsipGuardCtx, the decoder applies the
 * documented fallback when it is missing.  See README.md "uSIP mode". */

#ifndef USIP_DECODE_H
#define USIP_DECODE_H

#include <r_types.h>
#include <r_util.h>

#define USIP_MAX_UNITS 8
#define USIP_MAX_VALS 12
#define USIP_MAX_TAILS 3   /* 48-bit forms have two tails; the 64-bit packet-prefix forms three */

typedef struct usip_opcode_t UsipOpcode;

enum usip_pseudo {
	USIP_P_FORM = 0,   /* a table form (UsipInsn.op) */
	USIP_P_HWORD,      /* 16-bit unit without a reading */
	USIP_P_WORD,       /* head + tail without a reading */
	USIP_P_WORD_CTRL,  /* control-flow form whose tail is at the wrong distance or whose target guard failed (data) */
	USIP_P_W48,        /* head + hi + lo without a reading */
	USIP_P_LO,         /* context rule lo_after_hi */
	USIP_P_EXT,        /* context rule ext_after_ldst */
	USIP_P_BE79,       /* context rule be79_prefix (2 units) */
};

/* target-guard status of an instruction */
enum usip_guard {
	USIP_G_NONE = 0,   /* the form has no target guard (or it was not evaluated: greedy fallback) */
	USIP_G_OK,         /* the guard validated (target at a packet start of the function / at a function start) */
	USIP_G_UNVERIFIED, /* accepted by the fallback: the target could not be checked (printed with a trailing ?) */
};

typedef struct {
	ut8 head;               /* unit index of the head */
	ut8 ntails;             /* 0, 1, 2 (or 3 for the 64-bit prefix forms) */
	ut8 tails[USIP_MAX_TAILS]; /* unit indices of the tails (hi, lo) */
	ut8 pseudo;             /* enum usip_pseudo */
	ut8 guard;              /* enum usip_guard */
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

/* What the decoder may ask about branch targets (the target guards of the table).  Each callback answers
 * 1 = yes, 0 = no, -1 = unknown; a NULL callback means unknown.  Semantics of the answers:
 *   packet_start: the address is the start of a packet of the function being decoded;
 *   function_start: the address is the start of a function.
 * When the answer is unknown, a few forms are still read, marked USIP_G_UNVERIFIED (printed with a trailing ?): the
 * call / b / compare-and-branch-with-immediate forms whose F' = 0 tail sits at +2, beqz.d, the b<cond>.l prefix forms
 * and loop #N (their unverified readings are right in nearly every case, see unverified_ok in usip_decode.c); the
 * others (loop rX, far b, bnez.d, the register compare-and-branch, the 16-bit call.s) are data / fall through, as when
 * the guard fails. */
typedef struct {
	void *user;
	int (*packet_start)(void *user, ut64 addr);
	int (*function_start)(void *user, ut64 addr);
} UsipGuardCtx;

/* Collect the units of the packet that starts at buf (len bytes available).  Returns the number of units (0 when
 * len < 2) and sets *truncated when the close bit was not reached. */
int usip_scan_units(const ut8 *buf, int len, ut16 *units, bool *truncated);

/* Decode a whole packet (n units, 1..USIP_MAX_UNITS) starting at addr; g may be NULL (no target knowledge). */
void usip_decode_packet(UsipPacket *pk, ut64 addr, const ut16 *units, int n, bool truncated, const UsipGuardCtx *g);

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
const char *usip_csr_ext_name(int csr);

#endif
