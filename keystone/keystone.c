/* radare2-keystone - GPL - Copyright 2016 - pancake */

static void *oldcur = NULL;
static ks_engine *ks = NULL;
static int oldbit = 0;

static int keystone_assemble(RAsm *a, RAsmOp *ao, const char *str, ks_arch arch, ks_mode mode) {
	ks_err err = KS_ERR_ARCH;
	size_t count;
	size_t size;
	bool must_init = false;
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
			size = -1;
			goto beach;
		}
	}

	if (!ks) {
		size = -1;
		goto beach;
	}
	if (a->syntax == R_ASM_SYNTAX_ATT) {
		ks_option (ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
	} else {
		ks_option (ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
	}
	int rc = ks_asm (ks, str, a->pc, &insn, &size, &count);
	if (rc) {
		eprintf ("%s\n", ks_strerror ((ks_err)ks_errno (ks)));
		size = -1;
		goto beach;
	}
	memcpy (ao->buf, insn, size);
beach:
	ks_free (insn);
	ks_close (ks);
	ks = NULL;
	return size;
}
