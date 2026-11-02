/* radare2 - LGPL-3.0-only - Copyright 2026 - n0p */
/* scq16_vu.inc.c - the public model of the SCQ16 vector unit for the ESIL of the plugin (cpu=scq16).
 *
 * State (ESIL registers of the register profile):
 *   vr0-vr31   the vector register file: 32 registers of 128 bytes = 64 lanes of 16 bits each, exposed as four 256-bit
 *              quarters per register (`vrK_0` = lanes 0-15, `vrK_1` = 16-31,
 *              `vrK_2` = 32-47, `vrK_3` = 48-63; `ar vrK_q` prints the 32 bytes of a quarter as a little-endian number,
 *              so lane 16q is its low 16 bits);
 *   vp0-vp7    the VU pointers (written by vmem.set p_k, rs and by the hypothetical vcfg4c? #0xc);
 *   va0-va7    the VU count/modifier registers A (written by vset.a A_k, rs).
 * Operations modelled by the custom ESIL op `vop` (op9, A, B, F1, F2, F3), only for the three ESTABLISHED vector names of
 * the table (scq16_vname[op9] without `?`):
 *   v.mem.ld   vr[F1 >> 2][0 .. n) <- DM[p .. p + 2n): n = va[A] halves when 1 <= va[A] <= 64, else the whole register
 *              (va[A] = 0 or a larger packed parameter word: the count field of a large A is not established);
 *              p = vp[2 * F2 + F3[4]] for F2 < 4; the pointer is post-incremented by the bytes accessed;
 *   v.mem.st   DM[p .. p + 2n) <- vr0[0 .. n) (the data register is the implicit vr0), same pointer and count, same
 *              post-increment;
 *   v.move.mv  vr[F1] <- vr[F3] (the whole 128 bytes; the pair mode B = 2 is not modelled: an open reading).
 * A memory op with F2 >= 4 (the second access family, whose pointer is not established) and every other op9 pop their
 * operands and have no effect in the plugin (a strict emulator may stop on them instead).
 * Data memory is read and written through the ESIL memory callbacks (little-endian halves are copied as bytes: the lane
 * k of a register is bytes 2k, 2k + 1). */

#include <r_anal.h>          /* struct r_anal_t (esil->anal->reg): the vector register file lives in the register arena */

#define SCQ16_VR_N       32
#define SCQ16_VR_BYTES   128
#define SCQ16_VR_LANES   64
#define SCQ16_VR_QUARTER 32

/* the vector register file in the register profile: four 256-bit quarters per register; returns the next free offset */
static int scq16_vu_vr_profile(RStrBuf *sb, int off) {
	int k, q;
	for (k = 0; k < SCQ16_VR_N; k++) {
		for (q = 0; q < SCQ16_VR_BYTES / SCQ16_VR_QUARTER; q++, off += SCQ16_VR_QUARTER) {
			r_strbuf_appendf (sb, "gpr vr%d_%d .256 %d 0\n", k, q, off);
		}
	}
	return off;
}

/* pops the six operands of `vop` (pushed F3, F2, F1, B, A, op9: op9 on top) into v[0] = op9, v[1] = A, v[2] = B, v[3] = F1,
 * v[4] = F2, v[5] = F3 */
static bool scq16_vu_pop6(REsil *esil, ut64 *v) {
	int i;
	for (i = 0; i < 6; i++) {
		RStrs s = r_esil_pop (esil);
		if (r_strs_empty (s)) {
			return false;
		}
		char tmp[64];
		size_t l = r_strs_len (s);
		if (l >= sizeof (tmp)) {
			l = sizeof (tmp) - 1;
		}
		memcpy (tmp, s.a, l);
		tmp[l] = 0;
		v[i] = r_num_get (NULL, tmp);
	}
	return true;
}

/* the 128 bytes of vector register k in the register arena (NULL when the profile has no vector register file) */
static ut8 *scq16_vu_vr_bytes(REsil *esil, int k) {
	RReg *reg = (esil && esil->anal) ? esil->anal->reg : NULL;
	if (!reg) {
		return NULL;
	}
	char name[16];
	snprintf (name, sizeof (name), "vr%d_0", k & (SCQ16_VR_N - 1));
	RRegItem *ri = r_reg_get (reg, name, -1);
	if (!ri || ri->offset < 0 || ri->offset % 8 || ri->size != SCQ16_VR_QUARTER * 8) {
		return NULL;
	}
	RRegArena *a = reg->regset[ri->type].arena;
	size_t off = (size_t)ri->offset / 8;
	if (!a || !a->bytes || off + SCQ16_VR_BYTES > (size_t)a->size) {
		return NULL;
	}
	return a->bytes + off;
}

/* the count of a vector memory op in bytes: va[A] halves when 1..64, else the whole register */
static int scq16_vu_nbytes(ut64 cnt) {
	return (cnt == 0 || cnt > SCQ16_VR_LANES) ? SCQ16_VR_BYTES : (int)cnt * 2;
}

enum { SCQ16_VU_NONE = 0, SCQ16_VU_LD = 1, SCQ16_VU_ST = 2, SCQ16_VU_MV = 3 };

/* the public model: v = { op9, A, B, F1, F2, F3 }; returns SCQ16_VU_LD / ST / MV when the op was modelled (and executed), 0 when the
 * op9 is not one of the three established names (or a memory op of the second access family): the caller decides (no-op or stop). */
static int scq16_vu_vop_public(REsil *esil, const ut64 *v) {
	const int op9 = (int)(v[0] & 0x1ff), A = (int)(v[1] & 7), F1 = (int)(v[3] & 31), F2 = (int)(v[4] & 31), F3 = (int)(v[5] & 31);
	const char *nm = scq16_vname[op9];
	if (!nm || !scq16_vname_firm (nm)) {
		return SCQ16_VU_NONE;
	}
	if (!strcmp (nm, "mv")) {
		ut8 *dst = scq16_vu_vr_bytes (esil, F1), *src = scq16_vu_vr_bytes (esil, F3);
		if (!dst || !src) {
			return SCQ16_VU_NONE;
		}
		if (dst != src) {
			memmove (dst, src, SCQ16_VR_BYTES);
		}
		return SCQ16_VU_MV;
	}
	const bool ld = !strcmp (nm, "ld"), st = !strcmp (nm, "st");
	if ((!ld && !st) || F2 >= 4) {
		return SCQ16_VU_NONE;
	}
	const int j = 2 * F2 + ((F3 >> 4) & 1);
	char pname[8], aname[8];
	snprintf (pname, sizeof (pname), "vp%d", j);
	snprintf (aname, sizeof (aname), "va%d", A);
	ut64 p = 0, cnt = 0;
	if (!r_esil_reg_read (esil, pname, &p, NULL) || !r_esil_reg_read (esil, aname, &cnt, NULL)) {
		return SCQ16_VU_NONE;
	}
	if (esil->parse_stop) {           /* a strict executor refused an uninitialized pointer or count */
		return ld ? SCQ16_VU_LD : SCQ16_VU_ST;
	}
	const int nb = scq16_vu_nbytes (cnt);
	ut8 *vr = scq16_vu_vr_bytes (esil, ld ? (F1 >> 2) : 0);
	if (!vr) {
		return SCQ16_VU_NONE;
	}
	p &= 0xffffffffULL;
	if (ld) {
		ut8 buf[SCQ16_VR_BYTES];
		if (!r_esil_mem_read (esil, p, buf, nb)) {
			return SCQ16_VU_LD;
		}
		if (!esil->parse_stop) {
			memcpy (vr, buf, nb);
		}
	} else {
		if (!r_esil_mem_write (esil, p, vr, nb)) {
			return SCQ16_VU_ST;
		}
	}
	if (!esil->parse_stop) {
		r_esil_reg_write (esil, pname, (p + (ut64)nb) & 0xffffffffULL);
	}
	return ld ? SCQ16_VU_LD : SCQ16_VU_ST;
}
