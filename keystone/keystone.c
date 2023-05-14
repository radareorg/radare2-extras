/* radare2-keystone - GPL - Copyright 2016 - pancake */

#if R2_VERSION_NUMBER >= 50709
#define ATTSYNTAX R_ARCH_SYNTAX_ATT
#else
#define ATTSYNTAX R_ASM_SYNTAX_ATT
#endif

#include <r_th.h>

static R_TH_LOCAL void *oldcur = NULL;
static R_TH_LOCAL ks_engine *ks = NULL;
static R_TH_LOCAL int oldbit = 0;

static bool keystone_assemble(RArchSession *a, RAnalOp *ao, const char *str, ks_arch arch, ks_mode mode) {
	ks_err err = KS_ERR_ARCH;
	bool must_init = false;
	size_t count, size;
	ut8 *insn = NULL;

	if (!ks_arch_supported (arch)) {
		return false;
	}

	must_init = true; //!oldcur || (a->cur != oldcur || oldbit != a->bits);
	// oldcur = a->cur;
	oldbit = a->config->bits;

	if (must_init) {
		if (ks) {
			ks_close (ks);
			ks = NULL;
		}
		err = ks_open (arch, mode, &ks);
		if (err || !ks) {
			R_LOG_ERROR ("Cannot initialize keystone");
			ks_free (insn);
			if (ks) {
				ks_close (ks);
				ks = NULL;
			}
			return false;
		}
	}

	if (!ks) {
		ks_free (insn);
		if (ks) {
			ks_close (ks);
			ks = NULL;
		}
		return false;
	}
	if (a->config->syntax == ATTSYNTAX) {
		ks_option (ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
	} else {
		ks_option (ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
	}
	int rc = ks_asm (ks, str, ao->addr, &insn, &size, &count);
	if (rc) {
		eprintf ("ks_asm: (%s) %s\n", str, ks_strerror ((ks_err)ks_errno (ks)));
		ks_free (insn);
		if (ks) {
			ks_close (ks);
			ks = NULL;
		}
		return false;
	}
	ao->size = size;
	ao->bytes = r_mem_dup (insn, size);
	ks_free (insn);
	if (ks) {
		ks_close (ks);
		ks = NULL;
	}
	return size > 0;
}
