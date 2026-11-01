/* scq16_decode.h - decoder of the SCQ16 (MD32 family, byte-granular packet variant).
 *
 * Model: the minimum unit is the byte; an INSTRUCTION is a stand-alone unit, a PACKET {A ‖ B} of two units or an 8-byte
 * BUNDLE {vec32 ‖ s1 ‖ s2}.  Everything is decided by the first raw byte b0 and, when needed, a prefix of the second (the
 * leaves scq16_uleaves / scq16_hleaves of scq16_opcodes.h):
 *   00-7f  stand-alone scalar unit: L by the leaf U(b0, prefix of b1); forms of L bytes over w (bit 7 of byte 0 = 0).
 *   80-bf  scalar head: A' = (w << 1) | bit7(B) (bit 7 of the next byte is bit 0 of A'); leaf H(A'[0], prefix of A'[1])
 *          -> L(A') (head of L bytes + B slot) or a masked orphan (A' of control/system: the unit b0 & 0x7f of Lm bytes).
 *   c0-df  4-byte vector operation (110 A B F1 F2 F3 op9), never a head.
 *   e0-ef  4-byte vector head (A' = c0-df) + B slot.
 *   f0-f7  8-byte bundle {11 | vec32 w[61:30] | s1 w[29:15] | s2 w[14:0]}; s1/s2 = 2-byte units (7-bit opcode).
 *   f8-ff  masked orphan.
 * B slot: byte 0 masked (& 0x7f); L = 4 when the raw byte is c0-df, else the leaf U; its displacements are measured from the
 * packet start.  Packet semantics: PARALLEL (both slots read the previous state).  Delay slots (.d1/.d2): one/two
 * INSTRUCTIONS (packets included) after the control one.
 * Bit convention: w = big-endian integer of the transformed unit, bit 0 = LSB of the last byte. */
#ifndef SCQ16_DECODE_H
#define SCQ16_DECODE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "scq16_opcodes.h"

#define SCQ16_MAX_OPS 8

enum scq16_slot { SCQ16_S_UNIT = 0, SCQ16_S_A, SCQ16_S_B, SCQ16_S_ORPHAN, SCQ16_S_S1, SCQ16_S_S2 };
enum scq16_ikind { SCQ16_I_UNIT = 0, SCQ16_I_PACKET, SCQ16_I_BUNDLE };

typedef struct {
	uint32_t pc;              /* address of the first byte */
	uint8_t L;                /* length in bytes (0..8) */
	uint8_t slot;             /* enum scq16_slot */
	uint8_t raw[8];           /* bytes in memory */
	uint8_t b[8];             /* transformed bytes (A' in the head; byte 0 masked in a B slot or an orphan) */
	uint64_t w;               /* big-endian integer of b */
	const Scq16Alt *alt;      /* matching alternative, NULL = no form */
	int32_t vals[SCQ16_MAX_OPS];  /* operand values (register = number, immediate = value, disp = absolute target) */
	uint8_t nvals;
	uint32_t base;            /* base of the displacements (packet start) */
	uint8_t nb;               /* bit borrowed from B (heads) */
	bool has_target;
	uint32_t target;
	bool masked;              /* masked orphan (suffix .p) */
	bool last_head;           /* head without a B slot (end of the buffer): suffix ! */
	uint16_t op9;             /* vector operation: op9 */
	uint32_t vec32;           /* bundle: the 32-bit vector operation */
} Scq16Unit;

typedef struct {
	uint32_t addr;
	int size;                 /* bytes of the whole instruction (unit, packet or bundle); 0 = undecodable */
	uint8_t kind;             /* enum scq16_ikind */
	uint8_t n;                /* units: 1 (stand-alone), 2 (packet), 3 (bundle: vec, s1, s2) */
	Scq16Unit u[3];
	uint8_t delay;            /* delay slots of the instruction (the largest among its control units) */
	int need;                 /* bytes needed when size == 0 (truncated buffer) */
} Scq16Insn;

typedef const char *(*Scq16Symf)(void *user, uint32_t addr, char *buf, size_t n);

/* decode the instruction that starts at bytes[0] (address addr); len = bytes available.  Returns size (> 0), 0 when the
 * buffer is too short (out->need = bytes that would be needed) or -1 when the byte has no leaf. */
int scq16_decode_insn(const uint8_t *bytes, int len, uint32_t addr, Scq16Insn *out);
/* decode a transformed unit b of L bytes (low-level API: forms of L bytes over w, the first that matches) */
void scq16_decode_unit(Scq16Unit *u, const uint8_t *b, int L, uint32_t pc, uint32_t base, uint8_t slot);
/* length by leaf: stand-alone unit / masked B (b0 & 0x7f, b1); 0 when there is no leaf */
int scq16_uleaf(uint8_t b0, uint8_t b1);
/* head leaf: > 0 L(A'), < 0 masked orphan of -L bytes, 0 no leaf */
int scq16_hleaf(uint8_t a0, uint8_t a1);
/* mnemonic of the unit (v.<class>[.<name>?] for a vector operation; .p for a masked orphan, ! for a head without its B slot) */
const char *scq16_unit_mnemonic(const Scq16Unit *u, char *buf, size_t n);
/* operand text (the template of the alternative); sym = symbol of a target (NULL -> 0x%08x) */
int scq16_unit_operands(const Scq16Unit *u, char *buf, size_t n, Scq16Symf sym, void *user);
/* "mnemonic operands" of a unit; for the bundle: "vbundle v.class op9=.. ‖ s1 ‖ s2" */
int scq16_unit_text(const Scq16Unit *u, char *buf, size_t n, Scq16Symf sym, void *user);
int scq16_insn_text(const Scq16Insn *in, char *buf, size_t n, Scq16Symf sym, void *user);
/* operand by name: index in u->alt->ops or -1 */
int scq16_operand_index(const Scq16Unit *u, const char *name);
/* ESIL (radare2) of the unit: the template of the alternative with the operands substituted ({op} read, {=op} write, {#op} decimal value, {d}, {ret}, {mask}); remap = registers
 * that must be read from a temporary (parallel packet semantics: {reg, tmp} pairs, nremap pairs); ret = return address / start of
 * the do body (after the delay slots).  Returns the length or -1 when the form has no semantics. */
int scq16_unit_esil(const Scq16Unit *u, char *buf, size_t n, uint32_t ret, const char *const (*remap)[2], int nremap);
/* GPR/special registers written (dst) and read (src) by the ESIL of the unit: names in out[], returns how many */
int scq16_unit_esil_regs(const Scq16Unit *u, uint32_t ret, bool written, const char **out, int max);
/* ESIL registers of the VU (vu0-31, v0-31, va0-7, vp0-7, vs0-15, vb1_/vb3_/vb5_ 0-31, udf0-31): stable name or NULL; count and i-th name */
const char *scq16_vu_reg(const char *s);
/* hook that substitutes the ESIL template of an alternative (experiments): NULL = the template of the table */
extern const char *(*scq16_esil_override)(const Scq16Alt *a);
int scq16_vu_nregs(void);
const char *scq16_vu_name(int i);

#endif
