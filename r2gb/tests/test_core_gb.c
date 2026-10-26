/* radare2 - LGPL - Copyright 2026 - pancake */

#include <r_core.h>
#include "minunit.h"
#include "../apu.inc.c"
#include "../registers.inc.c"
#include "../instructions.inc.c"

static RCore *gameboy_core(ut8 cartridge, ut8 ram) {
	RCore *core = r_core_new ();
	char *plugin_path = r_sys_getenv ("R2GB_PLUGIN");
	bool loaded = r_lib_open (core->lib, R_STR_ISNOTEMPTY (plugin_path)? plugin_path: "./core_gb.r2so");
	free (plugin_path);
	if (!loaded) {
		r_core_free (core);
		return NULL;
	}
	if (!r_core_file_open (core, "malloc://0x10000", R_PERM_RWX, 0) || !r_core_bin_load (core, "malloc://0x10000", 0)) {
		r_core_free (core);
		return NULL;
	}
	r_config_set_b (core->config, "io.va", true);
	ut8 header[] = { cartridge, 1, ram };
	r_io_write_at (core->io, 0x147, header, sizeof (header));
	ut8 banks[] = { 0x11, 0x22, 0x33 };
	int i;
	for (i = 0; i < 3; i++) {
		r_io_write_at (core->io, (i + 1) * 0x4000, banks + i, 1);
	}
	r_core_call (core, "r2gb");
	return core;
}

static void gameboy_write_byte(RCore *core, ut16 addr, ut8 value) {
	r_esil_mem_write (&core->esil.esil, addr, &value, 1);
}

static ut8 gameboy_read_byte(RCore *core, ut16 addr) {
	ut8 value = 0;
	r_esil_mem_read (&core->esil.esil, addr, &value, 1);
	return value;
}

static bool gameboy_steps(RCore *core, int count) {
	int i;
	for (i = 0; i < count; i++) {
		if (!r_core_esil_single_step (core)) {
			return false;
		}
	}
	return true;
}

static bool test_gameboy_memory_and_banks(void) {
	RCore *core = gameboy_core (3, 3);
	mu_assert_notnull (core, "core");
	mu_assert_eq (core->io->bank, 1, "separate CPU bank");
	mu_assert_eq (gameboy_read_byte (core, 0x4000), 0x11, "initial ROM bank");
	const ut8 program[] = { 0x3e, 2, 0xea, 0, 0x20, 0xfa, 0, 0x40 };
	r_io_write_at (core->io, 0xc000, program, sizeof (program));
	r_reg_setv (core->anal->reg, "pc", 0xc000);
	mu_assert_true (gameboy_steps (core, 3), "execute bank switch through ESIL");
	mu_assert_eq (r_reg_getv (core->anal->reg, "a"), 0x22, "load from switched ROM bank");
	gameboy_write_byte (core, 0x2000, 0);
	mu_assert_eq (gameboy_read_byte (core, 0x4000), 0x11, "MBC1 bank zero selects bank one");
	gameboy_write_byte (core, 0xc123, 0x5a);
	mu_assert_eq (gameboy_read_byte (core, 0xe123), 0x5a, "work RAM echo");
	gameboy_write_byte (core, 0xe123, 0xa5);
	mu_assert_eq (gameboy_read_byte (core, 0xc123), 0xa5, "echo writes alias work RAM");
	mu_assert_eq (gameboy_read_byte (core, 0xa000), 0xff, "cartridge RAM initially disabled");
	gameboy_write_byte (core, 0, 0xa);
	gameboy_write_byte (core, 0xa000, 0x55);
	gameboy_write_byte (core, 0x6000, 1);
	gameboy_write_byte (core, 0x4000, 1);
	gameboy_write_byte (core, 0xa000, 0xaa);
	gameboy_write_byte (core, 0x4000, 0);
	mu_assert_eq (gameboy_read_byte (core, 0xa000), 0x55, "RAM bank zero preserved");
	gameboy_write_byte (core, 0x4000, 1);
	mu_assert_eq (gameboy_read_byte (core, 0xa000), 0xaa, "RAM bank one preserved");
	r_core_call (core, "r2gb-");
	mu_assert_eq (core->io->bank, 0, "restore analysis bank");
	mu_assert_null (r_flag_get (core->flags, "gb.framebuffer"), "remove framebuffer flag");
	mu_assert_streq (r_config_get (core->config, "cmd.esil.step"), "", "restore step hook");
	mu_assert_streq (r_config_get (core->config, "cmd.esil.stepout"), "", "restore step-out hook");
	r_core_free (core);
	mu_end;
}

static bool test_gameboy_resident_cartridge(void) {
	RCore *core = gameboy_core (3, 3);
	mu_assert_notnull (core, "core");
	int cartridge = r_bin_cur (core->bin)->fd;
	ut8 patched = 0x7a;
	mu_assert_eq (r_io_fd_write_at (core->io, cartridge, 0x4000, &patched, 1), 1, "patch original cartridge descriptor");
	mu_assert_eq (gameboy_read_byte (core, 0x4000), 0x11, "runtime reads resident cartridge copy");
	r_core_call (core, "r2gb");
	mu_assert_eq (gameboy_read_byte (core, 0x4000), patched, "reset reloads the cartridge");
	gameboy_write_byte (core, 0x2000, 2);
	mu_assert_eq (gameboy_read_byte (core, 0x4000), 0x22, "resident ROM bank switching");
	r_core_call (core, "r2gb-");
	mu_assert_notnull (r_io_desc_get (core->io, cartridge), "original descriptor remains open");
	r_core_free (core);
	mu_end;
}

static bool test_gameboy_lcd_and_timer(void) {
	RCore *core = gameboy_core (0, 0);
	mu_assert_notnull (core, "core");
	r_reg_setv (core->anal->reg, "pc", 0xc000);
	gameboy_write_byte (core, 0xff47, 0xe4);
	gameboy_write_byte (core, 0x8000, 0x80);
	mu_assert_true (gameboy_steps (core, 63), "render first scanline");
	ut8 pixels[6];
	mu_assert_true (r_io_read_at (core->io, 0x10000, pixels, sizeof (pixels)), "read framebuffer");
	mu_assert_eq (pixels[0], 170, "first pixel palette");
	mu_assert_eq (pixels[1], 170, "first pixel green");
	mu_assert_eq (pixels[2], 170, "first pixel blue");
	mu_assert_eq (pixels[3], 255, "second pixel background");
	gameboy_write_byte (core, 0xff0f, 0);
	gameboy_write_byte (core, 0xff04, 0);
	gameboy_write_byte (core, 0xff05, 0xff);
	gameboy_write_byte (core, 0xff06, 0x42);
	gameboy_write_byte (core, 0xff07, 5);
	mu_assert_true (gameboy_steps (core, 4), "timer cycles");
	mu_assert_eq (gameboy_read_byte (core, 0xff05), 0x42, "timer reload");
	mu_assert_true (gameboy_read_byte (core, 0xff0f) & 4, "timer interrupt request");
	gameboy_write_byte (core, 0xff07, 0);
	mu_assert_true (gameboy_steps (core, 16416 - 67), "advance to VBlank");
	mu_assert_eq (gameboy_read_byte (core, 0xff44), 144, "VBlank LY");
	mu_assert_true (gameboy_read_byte (core, 0xff0f) & 1, "VBlank interrupt request");
	r_core_free (core);
	mu_end;
}

static bool test_gameboy_interrupt_and_halt(void) {
	RCore *core = gameboy_core (0, 0);
	mu_assert_notnull (core, "core");
	const ut8 program[] = { 0xfb, 0, 0, 0x76, 0x3e, 0x55 };
	r_io_write_at (core->io, 0xc000, program, sizeof (program));
	r_reg_setv (core->anal->reg, "pc", 0xc000);
	gameboy_write_byte (core, 0xffff, 1);
	mu_assert_true (gameboy_steps (core, 1), "EI");
	mu_assert_eq (r_reg_getv (core->anal->reg, "ime"), 0, "EI is delayed");
	mu_assert_true (gameboy_steps (core, 1), "instruction after EI");
	mu_assert_eq (r_reg_getv (core->anal->reg, "ime"), 1, "EI takes effect");
	mu_assert_true (gameboy_steps (core, 1), "interrupt entry");
	mu_assert_eq (r_reg_getv (core->anal->reg, "pc"), 0x40, "VBlank vector");
	mu_assert_eq (r_reg_getv (core->anal->reg, "sp"), 0xfffc, "interrupt stack pointer");
	mu_assert_eq (gameboy_read_byte (core, 0xfffc), 2, "return address low byte");
	mu_assert_eq (gameboy_read_byte (core, 0xfffd), 0xc0, "return address high byte");
	mu_assert_eq (r_reg_getv (core->anal->reg, "ime"), 0, "interrupt clears IME");
	r_reg_setv (core->anal->reg, "pc", 0xc003);
	gameboy_write_byte (core, 0xff0f, 0);
	mu_assert_true (gameboy_steps (core, 3), "HALT idle");
	mu_assert_eq (r_reg_getv (core->anal->reg, "pc"), 0xc004, "HALT holds PC");
	gameboy_write_byte (core, 0xff0f, 1);
	mu_assert_true (gameboy_steps (core, 1), "HALT wake without IME");
	mu_assert_eq (r_reg_getv (core->anal->reg, "a"), 0x55, "wake executes next instruction");
	r_reg_setv (core->anal->reg, "pc", 0xc003);
	mu_assert_true (gameboy_steps (core, 2), "HALT bug");
	mu_assert_eq (r_reg_getv (core->anal->reg, "a"), 0x3e, "HALT bug duplicates opcode byte");
	mu_assert_eq (r_reg_getv (core->anal->reg, "pc"), 0xc005, "HALT bug suppresses increment");
	r_core_free (core);
	mu_end;
}

static bool test_gameboy_joypad_and_dma(void) {
	RCore *core = gameboy_core (0, 0);
	mu_assert_notnull (core, "core");
	gameboy_write_byte (core, 0xff00, 0x20);
	r_core_call (core, "r2gb keys 17");
	mu_assert_eq (gameboy_read_byte (core, 0xff00), 0xee, "direction row active low");
	gameboy_write_byte (core, 0xff00, 0x10);
	mu_assert_eq (gameboy_read_byte (core, 0xff00), 0xde, "button row active low");
	r_core_call (core, "r2gb keys 0");
	mu_assert_eq (gameboy_read_byte (core, 0xff00), 0xdf, "release buttons");
	gameboy_write_byte (core, 0xc000, 0x42);
	gameboy_write_byte (core, 0xff46, 0xc0);
	mu_assert_eq (gameboy_read_byte (core, 0xfe00), 0x42, "OAM DMA");
	r_core_call (core, "r2gb");
	mu_assert_eq (r_reg_getv (core->anal->reg, "pc"), 0x100, "reinitialize CPU");
	mu_assert_eq (core->io->bank, 1, "reinitialize IO bank");
	r_core_free (core);
	mu_end;
}

static bool test_gameboy_small_ram(void) {
	RCore *core = gameboy_core (3, 1);
	mu_assert_notnull (core, "core");
	gameboy_write_byte (core, 0, 0xa);
	gameboy_write_byte (core, 0xa123, 0x5a);
	mu_assert_eq (gameboy_read_byte (core, 0xb923), 0x5a, "2 KiB cartridge RAM read mirror");
	gameboy_write_byte (core, 0xb923, 0xa5);
	mu_assert_eq (gameboy_read_byte (core, 0xa123), 0xa5, "2 KiB cartridge RAM write mirror");
	r_core_free (core);
	mu_end;
}

static bool test_gameboy_screen_and_maps(void) {
	RCore *core = gameboy_core (3, 3);
	mu_assert_notnull (core, "core");
	r_config_set_i (core->config, "scr.color", 3);
	r_config_set_i (core->config, "hex.cols", 2);
	const ut8 red[] = { 255, 0, 0 };
	const ut8 blue[] = { 0, 0, 255 };
	r_io_write_at (core->io, 0x10000, red, sizeof (red));
	r_io_write_at (core->io, 0x10000 + 160 * 3, blue, sizeof (blue));
	gameboy_write_byte (core, 0x2000, 2);
	mu_assert_true (r_io_bank_use (core->io, 0), "select analysis bank");
	char *screen = r_core_cmd_str (core, "r2gb screen");
	mu_assert_notnull (screen, "screen command");
	mu_assert_true (r_str_startswith (screen, "\x1b[38;2;255;0;0m\x1b[48;2;0;0;255m▀"), "screen reads upper and lower pixels from framebuffer");
	r_str_ansi_strip (screen);
	mu_assert_eq (strlen (screen), 72 * (160 * strlen ("▀") + 1), "native screen dimensions ignore hex.cols");
	char *newline = strchr (screen, '\n');
	mu_assert_notnull (newline, "screen first row");
	mu_assert_eq (newline - screen, 160 * strlen ("▀"), "160 pixels per row");
	free (screen);
	char *maps = r_core_cmd_str (core, "r2gb maps");
	mu_assert_notnull (maps, "maps command");
	mu_assert_true (r_str_startswith (maps, "bank=1\n"), "maps refer to runtime bank");
	mu_assert ("active ROM bank offset", strstr (maps, "offset=0x00008000 gb.rom1"));
	mu_assert ("framebuffer region", strstr (maps, "0x00010000-0x00020dff rw-"));
	mu_assert ("framebuffer name", strstr (maps, "gb.framebuffer"));
	mu_assert ("work RAM echo", strstr (maps, "gb.echo"));
	free (maps);
	r_core_free (core);
	mu_end;
}

static bool test_gameboy_core_plugin_unload(void) {
	RCore *core = gameboy_core (0, 0);
	mu_assert_notnull (core, "core");
	mu_assert_eq (core->io->bank, 1, "runtime bank selected");
	RCorePlugin *plugin = NULL;
	RCorePluginSession *session;
	RListIter *iter;
	r_list_foreach (core->rcmd->libstore->plugins, iter, session) {
		if (!strcmp (session->plugin->meta.name, "r2gb")) {
			plugin = session->plugin;
			break;
		}
	}
	mu_assert_notnull (plugin, "registered Game Boy core plugin");
	mu_assert_true (r_core_plugin_remove (core->rcmd, plugin), "unload Game Boy core plugin");
	mu_assert_eq (core->io->bank, 0, "plugin unload restores analysis bank");
	mu_assert_null (r_flag_get (core->flags, "gb.framebuffer"), "plugin unload removes framebuffer");
	mu_assert_streq (r_config_get (core->config, "cmd.esil.step"), "", "plugin unload restores hooks");
	r_core_free (core);
	mu_end;
}


typedef struct {
	ut32 initialized;
	ut32 stopped;
	ut32 bytes;
	ut32 nonzero;
} GameBoyAudioBackend;

static RCmdResult gameboy_test_audio_call(RCmdContext *context) {
	RCorePluginSession *session = context->handler_user;
	GameBoyAudioBackend *backend = session->data;
	RCore *core = session->core;
	const char *input = context->subcmd.a;
	core->num->value = 0;
	if (*input == '?') {
		r_cons_println (context->cons, "auqi 44100 16 2");
		core->num->value = 1;
	} else if (*input == 'i') {
		backend->initialized++;
		core->num->value = 1;
	} else if (*input == '-') {
		backend->stopped++;
	} else if (*input == ' ') {
		ut64 address = r_num_math (core->num, r_cmdctx_arg (context, 0).a);
		ut64 length = r_num_math (core->num, r_cmdctx_arg (context, 1).a);
		ut8 samples[4096];
		if (length <= sizeof (samples) && r_io_read_at (core->io, address, samples, length)) {
			backend->bytes += length;
			int i;
			for (i = 0; i < length; i++) {
				backend->nonzero += samples[i] != 0;
			}
			core->num->value = length;
		} else {
			core->num->value = 0;
		}
	}
	return (RCmdResult) {0};
}

static bool test_gameboy_audio_memory(void) {
	RCore *core = gameboy_core (0, 0);
	mu_assert_notnull (core, "core");
	mu_assert_notnull (r_flag_get (core->flags, "gb.audio"), "mapped PCM buffer");
	gameboy_write_byte (core, 0xff40, 0);
	gameboy_write_byte (core, 0xff26, 0);
	gameboy_write_byte (core, 0xff26, 0x80);
	gameboy_write_byte (core, 0xff24, 0x77);
	gameboy_write_byte (core, 0xff25, 1);
	gameboy_write_byte (core, 0xff11, 0x80);
	gameboy_write_byte (core, 0xff12, 0xf0);
	gameboy_write_byte (core, 0xff13, 0);
	gameboy_write_byte (core, 0xff14, 0x87);
	mu_assert_eq (gameboy_read_byte (core, 0xff26), 0xf1, "trigger channel 1");
	mu_assert_eq (gameboy_read_byte (core, 0xff13), 0xff, "write-only period bits");
	const ut8 loop[] = { 0xc3, 0, 0xc0 };
	r_io_write_at (core->io, 0xc000, loop, sizeof (loop));
	r_reg_setv (core->anal->reg, "pc", 0xc000);
	mu_assert_true (gameboy_steps (core, 4096), "65536 cycles of sound with LCD off");
	char *status = r_core_cmd_str (core, "r2gb status");
	mu_assert ("44100 Hz output frame count", strstr (status, "audio=2756 offset=2756"));
	free (status);
	ut8 pcm[2756];
	mu_assert_true (r_io_read_at (core->io, GB_AUDIO_BUFFER, pcm, sizeof (pcm)), "read PCM memory");
	int i, crossings = 0;
	st16 previous = 0;
	bool positive = false, negative = false;
	for (i = 0; i < sizeof (pcm); i += 4) {
		mu_assert_eq (r_read_le16 (pcm + i), 0, "left speaker not routed");
		st16 right = r_read_le16 (pcm + i + 2);
		positive |= right > 1000;
		negative |= right < -1000;
		if (previous < 0 && right >= 0) {
			crossings++;
		}
		previous = right;
	}
	mu_assert_true (positive && negative, "audible bipolar waveform");
	mu_assert_eq (crossings, 8, "512 Hz pulse over 1/64 second");
	GameBoyAudioBackend backend = {0};
	RCorePlugin audio_plugin = {
		.meta = { .name = "audio" },
		.command = "auq",
		.call_ctx = gameboy_test_audio_call,
	};
	mu_assert_true (r_core_plugin_add (core->rcmd, &audio_plugin), "register PCM backend");
	RCorePluginSession *session = r_list_last (core->rcmd->libstore->plugins);
	session->data = &backend;
	r_core_call (core, "r2gb audio");
	mu_assert_eq (backend.initialized, 1, "open stereo streaming output");
	mu_assert_eq (backend.bytes, sizeof (pcm), "queue generated PCM");
	mu_assert_true (backend.nonzero > 0, "queue real waveform");
	mu_assert_streq (r_config_get (core->config, "asm.arch"), "gb", "audio leaves CPU architecture intact");
	r_core_call (core, "r2gb audio");
	mu_assert_eq (backend.initialized, 1, "reuse output device");
	mu_assert_eq (backend.bytes, sizeof (pcm), "do not replay consumed samples");
	mu_assert_true (gameboy_steps (core, 65536), "wrap PCM ring");
	r_core_call (core, "r2gb audio");
	mu_assert_eq (backend.bytes, sizeof (pcm) + GB_AUDIO_SIZE, "queue only retained PCM across ring wrap");
	r_core_call (core, "r2gb audio-");
	mu_assert_eq (backend.stopped, 1, "stop streaming output");
	r_core_call (core, "r2gb audio");
	mu_assert_eq (backend.initialized, 2, "restart streaming output");
	r_core_call (core, "r2gb-");
	mu_assert_null (r_flag_get (core->flags, "gb.audio"), "release PCM map and flag");
	mu_assert_eq (backend.stopped, 2, "emulator release closes audio output");
	mu_assert_true (r_core_plugin_remove (core->rcmd, &audio_plugin), "remove PCM backend");
	r_core_free (core);
	mu_end;
}

static bool test_gameboy_audio_controls(void) {
	GameBoyAPU apu = {0};
	gameboy_apu_write (&apu, 0xff26, 0x80);
	gameboy_apu_write (&apu, 0xff11, 0x3f);
	gameboy_apu_write (&apu, 0xff12, 0xf1);
	gameboy_apu_write (&apu, 0xff14, 0xc0);
	mu_assert_eq (gameboy_apu_read (&apu, 0xff26), 0xf1, "active channel status");
	gameboy_apu_frame (&apu);
	mu_assert_eq (gameboy_apu_read (&apu, 0xff26), 0xf0, "length expiry disables channel");
	gameboy_apu_write (&apu, 0xff14, 0x80);
	mu_assert_eq (gameboy_apu_read (&apu, 0xff26), 0xf1, "retrigger enables channel");
	int i;
	for (i = 0; i < 8; i++) {
		gameboy_apu_frame (&apu);
	}
	mu_assert_eq (apu.channel[0].volume, 14, "envelope decreases at 64 Hz");
	mu_assert_eq (gameboy_apu_read (&apu, 0xff12), 0xf1, "envelope leaves register unchanged");
	gameboy_apu_write (&apu, 0xff12, 0);
	mu_assert_eq (gameboy_apu_read (&apu, 0xff26), 0xf0, "DAC off disables channel");
	gameboy_apu_write (&apu, 0xff10, 0x11);
	gameboy_apu_write (&apu, 0xff12, 0xf0);
	gameboy_apu_write (&apu, 0xff13, 0xf8);
	gameboy_apu_write (&apu, 0xff14, 0x87);
	mu_assert_eq (gameboy_apu_read (&apu, 0xff26), 0xf0, "sweep overflow disables channel");
	gameboy_apu_write (&apu, 0xff30, 0xa5);
	gameboy_apu_write (&apu, 0xff26, 0);
	mu_assert_eq (gameboy_apu_read (&apu, 0xff26), 0x70, "APU power off");
	mu_assert_eq (gameboy_apu_read (&apu, 0xff12), 0, "power off clears sound registers");
	mu_assert_eq (gameboy_apu_read (&apu, 0xff30), 0xa5, "power off preserves wave RAM");
	gameboy_apu_write (&apu, 0xff12, 0xf0);
	mu_assert_eq (gameboy_apu_read (&apu, 0xff12), 0, "writes while off ignored");
	mu_end;
}

static bool test_gameboy_audio_wave_and_noise(void) {
	GameBoyAPU apu = {0};
	gameboy_apu_write (&apu, 0xff26, 0x80);
	gameboy_apu_write (&apu, 0xff1a, 0x80);
	gameboy_apu_write (&apu, 0xff1c, 0x20);
	gameboy_apu_write (&apu, 0xff30, 0xa5);
	gameboy_apu_write (&apu, 0xff1d, 0xff);
	gameboy_apu_write (&apu, 0xff1e, 0x87);
	ut8 sample[4];
	gameboy_apu_tick (&apu, sample);
	gameboy_apu_tick (&apu, sample);
	mu_assert_eq (apu.wave_sample, 5, "wave sequencer advances to low nibble");
	gameboy_apu_write (&apu, 0xff21, 0xf0);
	gameboy_apu_write (&apu, 0xff22, 0);
	gameboy_apu_write (&apu, 0xff23, 0x80);
	int i;
	for (i = 0; i < 8; i++) {
		gameboy_apu_tick (&apu, sample);
	}
	mu_assert_eq (apu.lfsr, 0x3fff, "noise shifts at divisor period");
	gameboy_apu_write (&apu, 0xff22, 8);
	gameboy_apu_write (&apu, 0xff23, 0x80);
	for (i = 0; i < 8; i++) {
		gameboy_apu_tick (&apu, sample);
	}
	mu_assert_eq (apu.lfsr, 0x3fbf, "short noise feeds bit 6");
	mu_end;
}

static bool test_gameboy_cached_esil(void) {
	RCore *core = gameboy_core (0, 0);
	mu_assert_notnull (core, "core");
	REsil *esil = &core->esil.esil;
	REsilRegInterface previous = esil->reg_if;
	GameBoyRegisters registers = {0};
	gameboy_registers_init (&registers, core);
	gameboy_register_set (esil, "af", 0x1230);
	mu_assert_eq (gameboy_register_get (esil, "a"), 0x12, "cached byte overlaps register pair");
	mu_assert_eq (gameboy_register_get (esil, "C"), 1, "cached flag overlaps F");
	gameboy_register_set (esil, "PC", 0x4321);
	mu_assert_eq (gameboy_register_get (esil, "mpc"), 0x4321, "PC alias uses full emulation PC");
	gameboy_register_set (esil, "mbcrom", 7);
	mu_assert_eq (gameboy_register_get (esil, "mbcrom"), 7, "uncached register falls back to original interface");
	mu_assert_true (r_esil_parse (esil, "0x42,a,="), "execute with cached register callbacks");
	mu_assert_eq (r_reg_getv (core->anal->reg, "a"), 0x42, "ESIL writes shared register arena");
	GameBoyInstruction *instructions = calloc (GB_INSTRUCTION_CACHE_SIZE, sizeof (GameBoyInstruction));
	mu_assert_notnull (instructions, "instruction cache");
	ut8 bytes[] = { 0xc3, 0x34, 0x12 };
	mu_assert_true (gameboy_instruction_decode (core, instructions, 0x100, bytes), "decode cached JP");
	mu_assert_true (r_esil_parse (esil, instructions->expression), "execute cached JP");
	mu_assert_eq (gameboy_register_get (esil, "pc"), 0x1234, "initial JP destination");
	bytes[1] = 0x78;
	bytes[2] = 0x56;
	mu_assert_true (gameboy_instruction_decode (core, instructions, 0x100, bytes), "bytes changed by patch or ROM bank switch");
	mu_assert_true (r_esil_parse (esil, instructions->expression), "execute changed JP");
	mu_assert_eq (gameboy_register_get (esil, "pc"), 0x5678, "changed bytes invalidate cached expression");
	ut64 key = instructions->key;
	mu_assert_true (gameboy_instruction_decode (core, instructions, 0x200, bytes), "decode same bytes at another PC");
	mu_assert_true (instructions->key != key, "instruction address participates in cache key");
	bytes[0] = 0xd3;
	mu_assert_false (gameboy_instruction_decode (core, instructions, 0x200, bytes), "reject illegal opcode after valid cache entry");
	gameboy_instructions_free (instructions);
	gameboy_registers_fini (&registers, core);
	mu_assert_ptreq (esil->reg_if.reg, previous.reg, "restore register interface context");
	mu_assert_ptreq (esil->reg_if.reg_read, previous.reg_read, "restore register read callback");
	r_core_free (core);
	mu_end;
}

int main(int argc, char **argv) {
	mu_run_test (test_gameboy_memory_and_banks);
	mu_run_test (test_gameboy_resident_cartridge);
	mu_run_test (test_gameboy_lcd_and_timer);
	mu_run_test (test_gameboy_interrupt_and_halt);
	mu_run_test (test_gameboy_joypad_and_dma);
	mu_run_test (test_gameboy_small_ram);
	mu_run_test (test_gameboy_screen_and_maps);
	mu_run_test (test_gameboy_core_plugin_unload);
	mu_run_test (test_gameboy_audio_memory);
	mu_run_test (test_gameboy_audio_controls);
	mu_run_test (test_gameboy_audio_wave_and_noise);
	mu_run_test (test_gameboy_cached_esil);
	return tests_passed != tests_run;
}
