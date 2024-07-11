
#ifdef PK_IOD_EMMAP
#define GNUPOKE 4
#else
#define GNUPOKE 3
#endif

/* Terminal hook that flushes the terminal.  */

/* Terminal hook that prints a fixed string.  */

static bool stderr_mode = false;

#if GNUPOKE == 4
static void poke_term_flush(pk_compiler pkc) {
	/* Do nothing here.  */
	// r_cons_flush ();
}

static void poke_puts(pk_compiler pkc, const char *str) {
	if (stderr_mode) {
		eprintf ("%s", str);
	} else {
		r_cons_printf ("%s", str);
	}
}
/* Terminal hook that prints a formatted string.  */

__attribute__ ((__format__ (__printf__, 2, 3)))
static void poke_printf (pk_compiler pkc, const char *format, ...) {
	va_list ap;
	char *str;

	va_start (ap, format);
	int r = vasprintf (&str, format, ap);
	va_end (ap);
	if (r == -1) {
		R_LOG_ERROR ("out of memory in vasprintf"); /* XXX fatal */
		return;
	}
	poke_puts (pkc, str);
	free (str);
}
/* Terminal hook that indents to a given level.  */

static void poke_term_indent (pk_compiler pkc, unsigned int lvl, unsigned int step) {
	r_cons_printf ("\n%*s", (step * lvl), "");
}

/* Terminal hook that starts a styling class.  */

static void poke_term_class (pk_compiler pkc, const char *class_name) {
	if (!strcmp (class_name, "stderr")) {
		stderr_mode = true;
	}
	// eprintf ("STYLE.BEG (%s)\n", class_name);
	// TODO: add styling class to print message to stderr instead
	/* Do nothing here.  */
}

/* Terminal hook that finishes a styling class.  */

static int poke_term_end_class (pk_compiler pkc, const char *class_name) {
	if (!strcmp (class_name, "stderr")) {
		stderr_mode = false;
	}
	// eprintf ("STYLE.END (%s)\n", class_name);
	return 1;
}

/* Terminal hook that starts a terminal hyperlink.  */

static void poke_term_hyperlink (pk_compiler pkc, const char *url, const char *id) {
	/* Do nothing here.  */
}

/* Terminal hook that finishes a terminal hyperlink.  */
static int poke_term_end_hyperlink (pk_compiler pkc) {
	/* Just report success.  */
	return 1;
}

/* Terminal hook that returns the current terminal foreground color */
static struct pk_color poke_term_get_color (pk_compiler pkc) {
	/* Just return the default foreground color.  */
	struct pk_color dfl = {-1,-1,-1};
	return dfl;
}

/* Terminal hook that returns the current terminal background
   color.  */

static struct pk_color poke_term_get_bgcolor (pk_compiler pkc) {
	/* Just return the default background color.  */
	struct pk_color dfl = {-1,-1,-1};
	return dfl;
}

/* Terminal hook that sets the terminal foreground color.  */

static void poke_term_set_color (pk_compiler pkc, struct pk_color color) {
	/* Do nothing.  */
}

/* Terminal hook that sets the terminal background color.  */

static void poke_term_set_bgcolor (pk_compiler pkc, struct pk_color color) {
	/* Do nothing.  */
}

#else
static void poke_term_flush(void) {
	/* Do nothing here.  */
	// r_cons_flush ();
}

static void poke_puts(const char *str) {
	if (stderr_mode) {
		eprintf ("%s", str);
	} else {
		r_cons_printf ("%s", str);
	}
}
/* Terminal hook that prints a formatted string.  */

__attribute__ ((__format__ (__printf__, 1, 2)))
static void poke_printf (const char *format, ...) {
	va_list ap;
	char *str;

	va_start (ap, format);
	int r = vasprintf (&str, format, ap);
	va_end (ap);
	if (r == -1) {
		R_LOG_ERROR ("out of memory in vasprintf"); /* XXX fatal */
		return;
	}
	poke_puts (str);
	free (str);
}


/* Terminal hook that indents to a given level.  */

static void poke_term_indent (unsigned int lvl, unsigned int step) {
	r_cons_printf ("\n%*s", (step * lvl), "");
}

/* Terminal hook that starts a styling class.  */

static void poke_term_class (const char *class_name) {
	if (!strcmp (class_name, "stderr")) {
		stderr_mode = true;
	}
	// eprintf ("STYLE.BEG (%s)\n", class_name);
	// TODO: add styling class to print message to stderr instead
	/* Do nothing here.  */
}

/* Terminal hook that finishes a styling class.  */

static int poke_term_end_class (const char *class_name) {
	if (!strcmp (class_name, "stderr")) {
		stderr_mode = false;
	}
	// eprintf ("STYLE.END (%s)\n", class_name);
	return 1;
}

/* Terminal hook that starts a terminal hyperlink.  */

static void poke_term_hyperlink (const char *url, const char *id) {
	/* Do nothing here.  */
}

/* Terminal hook that finishes a terminal hyperlink.  */
static int poke_term_end_hyperlink (void) {
	/* Just report success.  */
	return 1;
}

/* Terminal hook that returns the current terminal foreground color */
static struct pk_color poke_term_get_color (void) {
	/* Just return the default foreground color.  */
	struct pk_color dfl = {-1,-1,-1};
	return dfl;
}

/* Terminal hook that returns the current terminal background
   color.  */

static struct pk_color poke_term_get_bgcolor (void) {
	/* Just return the default background color.  */
	struct pk_color dfl = {-1,-1,-1};
	return dfl;
}

/* Terminal hook that sets the terminal foreground color.  */

static void poke_term_set_color (struct pk_color color) {
	/* Do nothing.  */
}

/* Terminal hook that sets the terminal background color.  */

static void poke_term_set_bgcolor (struct pk_color color) {
	/* Do nothing.  */
}

#endif


/* Implementation of the poke terminal interface, that uses the hooks
   defined above.  */

static struct pk_term_if poke_term_if = {
	.flush_fn = poke_term_flush,
	.puts_fn = poke_puts,
	.printf_fn = poke_printf,
	.indent_fn = poke_term_indent,
	.class_fn = poke_term_class,
	.end_class_fn = poke_term_end_class,
	.hyperlink_fn = poke_term_hyperlink,
	.end_hyperlink_fn = poke_term_end_hyperlink,
	.get_color_fn = poke_term_get_color,
	.get_bgcolor_fn = poke_term_get_bgcolor,
	.set_color_fn = poke_term_set_color,
	.set_bgcolor_fn = poke_term_set_bgcolor,
};
