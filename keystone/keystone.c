/* radare2-keystone - GPL - Copyright 2016 - pancake */

static void *oldcur = NULL;
static ks_engine *ks = NULL;
static int oldbit = 0;

static int keystone_assemble(RAsm *a, RAsmOp *ao, const char *str, ks_arch arch, ks_mode mode) {
	ks_err err = KS_ERR_ARCH;
	bool must_init = false;
	size_t count, size;
	ut8 *insn = NULL;

	if (!ks_arch_supported (arch)) {
		return -1;
	}

	must_init = true; //!oldcur || (a->cur != oldcur || oldbit != a->bits);
	oldcur = a->cur;
	oldbit = a->bits;

	if (must_init) {
		if (ks) {
			ks_close (ks);
			ks = NULL;
		}
		err = ks_open (arch, mode, &ks);
		if (err || !ks) {
			eprintf ("Cannot initialize keystone\n");
			ks_free (insn);
			if (ks) {
				ks_close (ks);
				ks = NULL;
			}
			return -1;
		}
	}

	if (!ks) {
		ks_free (insn);
		if (ks) {
			ks_close (ks);
			ks = NULL;
		}
		return -1;
	}
	if (a->syntax == R_ASM_SYNTAX_ATT) {
		ks_option (ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
	} else {
		ks_option (ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
	}
	int rc = ks_asm (ks, str, a->pc, &insn, &size, &count);
	if (rc) {
		eprintf ("ks_asm: (%s) %s\n", str, ks_strerror ((ks_err)ks_errno (ks)));
		ks_free (insn);
		if (ks) {
			ks_close (ks);
			ks = NULL;
		}
		return -1;
	}
	memcpy (ao->buf, insn, R_MIN (size, sizeof (ao->buf) -1));
	ks_free (insn);
	if (ks) {
		ks_close (ks);
		ks = NULL;
	}
	return size;
}
