/* radare2 - LGPL-3.0-only - Copyright 2026 - pancake */
#define R2_PLUGIN_INCORE
#include "../core_tama.c"

#define CHECK(x) do { if (!(x)) { fprintf (stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); return false; } } while (0)

static RCore *new_core(const char *file) {
	RCore *core = r_core_new ();
	r_config_set_i (core->config, "scr.color", 0);
	if (!r_core_file_open (core, file, R_PERM_RWX, 0) || !tama_init (core)) {
		r_core_free (core);
		return NULL;
	}
	return core;
}

static bool test_isa(void) {
	RCore *core = new_core ("malloc://12288");
	CHECK (core);
	RCoreTama *tama = tama_get (&core->esil.esil);
	REsil *esil = &core->esil.esil;
	char *step = esil->cmd_step;
	esil->cmd_step = NULL;
	unsigned word, trial, accepted = 0;
	ut32 random = 0x6200;
	for (word = 0; word < 4096; word++) {
		ut8 bytes[2];
		r_write_le16 (bytes, word);
		RAnalOp op;
		r_anal_op_init (&op);
		r_anal_op_set_bytes (&op, 0x2fe, bytes, 2);
		if (!r_arch_session_decode (core->anal->arch->session, &op, R_ARCH_OP_MASK_ALL)) {
			r_anal_op_fini (&op);
			continue;
		}
		accepted++;
		RAnalOp encoded;
		r_anal_op_init (&encoded);
		encoded.mnemonic = strdup (op.mnemonic);
		CHECK (r_arch_session_encode (core->anal->arch->session, &encoded, 0));
		CHECK (encoded.size == 2 && r_read_le16 (encoded.bytes) == word);
		r_anal_op_fini (&encoded);
		for (trial = 0; trial < 8; trial++) {
			ut8 data[640];
			unsigned j;
			for (j = 0; j < sizeof (data); j++) {
				random = random * 1664525 + 1013904223;
				data[j] = random >> 28;
			}
			r_io_fd_write_at (tama->io, tama->data_fd, 0, data, sizeof (data));
			tama_set_reg (tama, "pc", 0x300);
			tama_set_reg (tama, "x", 0x121);
			tama_set_reg (tama, "y", 0x123);
			tama_set_reg (tama, "a", trial * 2);
			tama_set_reg (tama, "b", 15 - trial);
			tama_set_reg (tama, "f", trial * 2 + (trial & 1));
			tama_set_reg (tama, "sp", 0xfe);
			tama_set_reg (tama, "np", 3);
			tama_set_reg (tama, "pn", 0x2fe);
			tama_set_reg (tama, "halted", 0);
			tama_set_reg (tama, "sleeping", 0);
			esil->trap = 0;
			const char *expression = r_strbuf_get (&op.esil);
			CHECK (!*expression || r_esil_parse (esil, expression));
			CHECK (!esil->trap && !esil->stackptr);
			if (word == 0xff9) {
				CHECK (tama_reg (tama, "halted") == 1 && tama_reg (tama, "sleeping") == 1);
			}
		}
		r_anal_op_fini (&op);
	}
	esil->cmd_step = step;
	printf ("ISA: %u encodings round-trip and execute without ESIL traps over 8 states\n", accepted);
	r_core_free (core);
	return true;
}

static bool test_nops(void) {
	RCore *core = new_core ("malloc://12288");
	CHECK (core);
	RCoreTama *tama = tama_get (&core->esil.esil);
	ut8 program[6];
	r_write_le16 (program, 0xffb);
	r_write_le16 (program + 2, 0xfff);
	r_write_le16 (program + 4, 0xe07);
	r_io_fd_write_at (core->io, tama->rom_fd, 0x200, program, sizeof (program));
	CHECK (tama_step (tama));
	CHECK (tama_reg (tama, "pc") == 0x202 && tama->cycles == 5 && tama->ticks == 5);
	CHECK (tama_step (tama));
	CHECK (tama_reg (tama, "pc") == 0x204 && tama->cycles == 12 && tama->ticks == 12);
	CHECK (tama_step (tama));
	CHECK (tama_reg (tama, "a") == 7 && !tama->failed);
	r_core_free (core);
	puts ("CPU: empty-ESIL NOP5/NOP7 advance PC and hardware clocks");
	return true;
}

static bool test_hardware(void) {
	RCore *core = new_core ("malloc://12288");
	CHECK (core);
	RCoreTama *tama = tama_get (&core->esil.esil);
	ut32 previous_bank = tama->previous_bank;
	CHECK (core->io->bank != previous_bank);
	CHECK (r_flag_get (core->flags, "tama.hw.K0")->addr == TAMA_DATA + 0xf40);
	CHECK (tama_data_read (tama, 0xf40) == 15);
	tama_data_write (tama, 0xf14, 7);
	tama_keys (tama, 1 | 2);
	CHECK (tama_data_read (tama, 0xf40) == 9);
	CHECK (tama_data_read (tama, 0xf04) == 1);
	CHECK (!tama_data_read (tama, 0xf04));
	tama_keys (tama, 0);
	CHECK (tama_data_read (tama, 0xf40) == 15);
	// Timer flags, counters and HALT wakeup use OSC1 clocks.
	tama_tick (tama, TAMA_HZ);
	CHECK (tama_data_read (tama, 0xf00) == 15);
	CHECK (!tama_data_read (tama, 0xf00));
	CHECK (tama_data_read (tama, 0xf20) == 0 && tama_data_read (tama, 0xf21) == 0);
	tama_data_write (tama, 0xf10, 8);
	tama_factor (tama, 0, 8);
	tama_set_reg (tama, "pc", 0x246);
	tama_set_reg (tama, "sp", 1);
	tama_set_reg (tama, "I", 1);
	tama_set_reg (tama, "halted", 1);
	CHECK (tama_step (tama));
	CHECK (tama_reg (tama, "pc") == 0x204 && !tama_reg (tama, "halted"));
	CHECK (tama_reg (tama, "sp") == 0xfe && !tama_reg (tama, "I"));
	CHECK (tama_data_read (tama, 0xfe) == 3 && tama_data_read (tama, 0xff) == 2 && tama_data_read (tama, 0) == 1);
	tama_data_read (tama, 0xf00);
	tama_data_write (tama, 0xf26, 2);
	tama_data_write (tama, 0xf79, 2);
	tama_data_write (tama, 0xf78, 3);
	tama_tick (tama, 128);
	CHECK (tama_data_read (tama, 0xf24) == 1);
	tama_tick (tama, 128);
	CHECK (tama_data_read (tama, 0xf24) == 2 && tama_data_read (tama, 0xf02) == 1);
	// Rotate reads a clear-on-read MMIO operand once before computing carry.
	ut8 rotate[2];
	r_write_le16 (rotate, 0xafa);
	r_io_fd_write_at (tama->io, tama->rom_fd, 0x200, rotate, sizeof (rotate));
	tama_set_reg (tama, "pc", 0x200);
	tama_set_reg (tama, "x", 0xf00);
	tama_set_reg (tama, "f", 0);
	tama_hw_set (tama, 0, 8);
	CHECK (tama_step (tama));
	CHECK (tama_reg (tama, "C") == 1 && !tama_data_read (tama, 0xf00));
	// Segment wiring, icon wiring and ALON precedence over ALOFF.
	tama_data_write (tama, 0xf71, 0);
	tama_data_write (tama, 0xe00, 1);
	tama_data_write (tama, 0xe10, 2);
	ut8 pixel[3];
	r_io_read_at (core->io, TAMA_FRAMEBUFFER, pixel, sizeof (pixel));
	CHECK (pixel[0] == 255 && pixel[1] == 255 && pixel[2] == 255);
	CHECK (tama->icons == 2);
	tama_data_write (tama, 0xf71, 8);
	r_io_read_at (core->io, TAMA_FRAMEBUFFER, pixel, sizeof (pixel));
	CHECK (!pixel[0] && !tama->icons);
	tama_data_write (tama, 0xf71, 12);
	r_io_read_at (core->io, TAMA_FRAMEBUFFER + TAMA_FRAME_SIZE - 3, pixel, sizeof (pixel));
	CHECK (pixel[0] == 255 && tama->icons == 255);
	// A gated speaker is silent; enabling it generates signed stereo PCM.
	tama_audio_flush (tama);
	ut64 before = tama->audio_produced;
	tama_data_write (tama, 0xf54, 7);
	tama_tick (tama, 64);
	tama_audio_flush (tama);
	ut8 samples[256];
	r_io_fd_read_at (core->io, tama->audio_fd, before % TAMA_AUDIO_SIZE, samples, sizeof (samples));
	CHECK (!r_mem_is_zero (samples, sizeof (samples)));
	unsigned i;
	for (i = 0; i < sizeof (samples); i += 4) {
		CHECK (r_read_le16 (samples + i) == r_read_le16 (samples + i + 2));
	}
	ut64 ticks = tama->ticks;
	tama_data_write (tama, 0xf70, 8);
	tama_tick (tama, 1000);
	CHECK (tama->ticks - ticks == 32);
	CHECK (tama_init (core));
	tama = tama_get (&core->esil.esil);
	CHECK (tama->ticks == 0 && tama->interrupts == 0 && tama_reg (tama, "pc") == 0x200);
	r_esil_plugin_deactivate (&core->esil.esil, "tamagotchi");
	CHECK (core->io->bank == previous_bank);
	CHECK (!r_flag_get (core->flags, "tama.hw.K0"));
	CHECK (!r_flag_get (core->flags, "tama.framebuffer"));
	CHECK (!strcmp (r_config_get (core->config, "cmd.esil.step"), ""));
	r_core_free (core);
	puts ("Hardware: RAM, LCD, icons, buttons, timers, HALT, interrupts, PCM and reset passed");
	return true;
}

static bool test_icons(void) {
	RCore *core = new_core ("malloc://12288");
	CHECK (core);
	RCoreTama *tama = tama_get (&core->esil.esil);
	CHECK (r_flag_get (core->flags, "tama.screen")->addr == TAMA_SCREEN_BUFFER);
	tama_data_write (tama, 0xf71, 0);
	tama_data_write (tama, 0xe00, 1);
	ut8 rgb[3];
	ut64 matrix = TAMA_SCREEN_BUFFER + (24 * TAMA_SCREEN_WIDTH + 16) * 3;
	r_io_read_at (core->io, matrix, rgb, sizeof (rgb));
	CHECK (rgb[0] == 255 && rgb[1] == 255 && rgb[2] == 255);
	int selected, icon, x, y;
	for (selected = 0; selected < 8; selected++) {
		tama_data_write (tama, 0xe10, selected < 4? 1 << selected: 0);
		tama_data_write (tama, 0xeb9, selected >= 4? 1 << (selected - 4): 0);
		CHECK (tama->icons == 1 << selected);
		ut8 bits;
		r_io_read_at (core->io, TAMA_FRAMEBUFFER + TAMA_FRAME_SIZE, &bits, 1);
		CHECK (bits == 1 << selected);
		for (icon = 0; icon < 8; icon++) {
			int left = (icon % 4) * 32, top = icon < 4? 0: 74;
			ut64 border = TAMA_SCREEN_BUFFER + (top * TAMA_SCREEN_WIDTH + left + 3) * 3;
			r_io_read_at (core->io, border, rgb, sizeof (rgb));
			CHECK (rgb[0] == (selected == icon? 255: 0));
			bool found = false;
			for (y = 0; y < 18 && !found; y++) {
				for (x = 0; x < 22; x++) {
					if ((tama_icon_pixels[icon][y] >> x) & 1) {
						ut64 dot = TAMA_SCREEN_BUFFER + ((top + 2 + y) * TAMA_SCREEN_WIDTH + left + 5 + x) * 3;
						r_io_read_at (core->io, dot, rgb, sizeof (rgb));
						CHECK (rgb[0] == (selected == icon? 255: 112));
						found = true;
						break;
					}
				}
			}
			CHECK (found);
		}
	}
	tama_data_write (tama, 0xf71, 8);
	CHECK (!tama->icons);
	r_io_read_at (core->io, matrix, rgb, sizeof (rgb));
	CHECK (!rgb[0]);
	char *screen = tama_screen_fit (tama, 80, 20);
	CHECK (screen);
	int lines = 0;
	const char *p;
	for (p = screen; *p; p++) {
		lines += *p == '\n';
	}
	CHECK (lines <= 20);
	free (screen);
	r_esil_plugin_deactivate (&core->esil.esil, "tamagotchi");
	CHECK (!r_flag_get (core->flags, "tama.screen"));
	r_core_free (core);
	puts ("Icons: all eight LCD segment controls select the matching pictogram and border");
	return true;
}

static bool rom_loads_as(const char *uri, const ut8 *expected) {
	RCore *core = new_core (uri);
	CHECK (core);
	RCoreTama *tama = tama_get (&core->esil.esil);
	ut8 rom[0x3000];
	const bool same = r_io_fd_read_at (tama->io, tama->rom_fd, 0, rom, sizeof (rom)) == sizeof (rom)
		&& !memcmp (rom, expected, sizeof (rom));
	r_core_free (core);
	CHECK (same);
	return true;
}

static bool rom_format(const char *name, const ut8 *buf, size_t size, const char *scheme, const ut8 *expected) {
	char *path = r_file_temp_ex ("r2tama", name);
	CHECK (path && r_file_dump (path, buf, size, false));
	char *uri = r_str_newf ("%s%s", scheme, path);
	const bool ok = rom_loads_as (uri, expected);
	r_file_rm (path);
	free (uri);
	free (path);
	CHECK (ok);
	return true;
}

// the same rom as le16 and be16 units, packed le and be 12-bit streams
static bool test_rom_formats(const char *file) {
	size_t size = 0;
	ut8 *rom = (ut8 *)r_file_slurp (file, &size);
	CHECK (rom && size == 0x3000);
	ut8 be16[0x3000];
	ut8 packed[TAMA_PACKED_ROM_SIZE];
	size_t i;
	for (i = 0; i < size; i += 2) {
		r_write_be16 (be16 + i, r_read_le16 (rom + i));
	}
	bool ok = rom_format (".le16", rom, size, "", rom)
		&& rom_format (".be16", be16, size, "", rom)
		&& rom_format (".le16", rom, size, "bits://16/", rom)
		&& r_mem_pack_bits (packed, rom, 6144, 12, false)
		&& rom_format (".le12", packed, sizeof (packed), "bits://12/", rom)
		&& r_mem_pack_bits (packed, be16, 6144, 12, true)
		&& rom_format (".be12", packed, sizeof (packed), "bits://12be/", rom);
	if (ok) {
		char *path = r_file_temp_ex ("r2tama", ".raw12");
		ok = path && r_file_dump (path, packed, sizeof (packed), false);
		RCore *core = ok? r_core_new (): NULL;
		ok = core && r_core_file_open (core, path, R_PERM_R, 0) && !tama_init (core);
		r_core_free (core);
		r_file_rm (path);
		free (path);
	}
	free (rom);
	CHECK (ok);
	printf ("%s: loads as le16, be16 and packed bits://12/ and bits://12be/\n", file);
	return true;
}

static bool test_rom(const char *file) {
	RCore *core = new_core (file);
	CHECK (core);
	RCoreTama *tama = tama_get (&core->esil.esil);
	ut64 deadline = 20 * TAMA_HZ;
	while (tama->ticks < deadline) {
		CHECK (tama_step (tama));
	}
	ut8 pixels[TAMA_FRAME_SIZE];
	r_io_fd_read_at (tama->io, tama->frame_fd, 0, pixels, sizeof (pixels));
	unsigned lit = 0, i;
	for (i = 0; i < sizeof (pixels); i += 3) {
		lit += pixels[i] != 0;
	}
	printf ("%s: pc=%04llx ticks=%llu interrupts=%llu lit=%u\n", file, tama_reg (tama, "pc"), tama->ticks, tama->interrupts, lit);
	CHECK (lit > 0 && lit < 512 && tama->interrupts > 0);
	ut8 before[TAMA_FRAME_SIZE];
	memcpy (before, pixels, sizeof (pixels));
	tama_keys (tama, 2);
	deadline = tama->ticks + TAMA_HZ / 4;
	while (tama->ticks < deadline) {
		CHECK (tama_step (tama));
	}
	tama_keys (tama, 0);
	deadline = tama->ticks + TAMA_HZ;
	while (tama->ticks < deadline) {
		CHECK (tama_step (tama));
	}
	r_io_fd_read_at (tama->io, tama->frame_fd, 0, pixels, sizeof (pixels));
	CHECK (memcmp (before, pixels, sizeof (pixels)));
	const char *long_seconds = getenv ("R2TAMA_LONG_SECONDS");
	if (long_seconds) {
		// Confirm the default clock with C, then let the firmware hatch the egg.
		tama_keys (tama, 4);
		deadline = tama->ticks + TAMA_HZ / 4;
		while (tama->ticks < deadline) {
			CHECK (tama_step (tama));
		}
		tama_keys (tama, 0);
		deadline = tama->ticks + strtoul (long_seconds, NULL, 10) * TAMA_HZ;
		while (tama->ticks < deadline) {
			CHECK (tama_step (tama));
		}
		CHECK (!tama->failed);
		r_io_fd_read_at (tama->io, tama->frame_fd, 0, pixels, sizeof (pixels));
		CHECK (!r_mem_is_zero (pixels, sizeof (pixels)));
		printf ("%s: long run ticks=%llu pc=%04llx interrupts=%llu\n", file, tama->ticks, tama_reg (tama, "pc"), tama->interrupts);
	}
	tama_audio_flush (tama);
	CHECK (tama->audio_produced > 0);
	r_core_free (core);
	return true;
}

int main(int argc, char **argv) {
	if (!test_isa () || !test_nops () || !test_hardware () || !test_icons ()) {
		return 1;
	}
	int i;
	for (i = 1; i < argc; i++) {
		if (!test_rom_formats (argv[i]) || !test_rom (argv[i])) {
			return 1;
		}
	}
	return 0;
}
