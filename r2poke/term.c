
/* Terminal hook that flushes the terminal.  */

static void poke_term_flush(void) {
	/* Do nothing here.  */
	// r_cons_flush ();
}

/* Terminal hook that prints a fixed string.  */

static void poke_puts(const char *str) {
	r_cons_printf ("%s", str);
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

	r_cons_printf ("%s", str);
	free (str);
}

/* Terminal hook that indents to a given level.  */

static void poke_term_indent (unsigned int lvl, unsigned int step) {
	r_cons_printf ("\n%*s", (step * lvl), "");
}

/* Terminal hook that starts a styling class.  */

static void poke_term_class (const char *class_name) {
	/* Do nothing here.  */
}

/* Terminal hook that finishes a styling class.  */

static int poke_term_end_class (const char *class_name) {
	/* Just report success.  */
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
