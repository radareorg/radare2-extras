/* radare2 - LGPL-3.0-only - Copyright 2026 - pancake */

#include <r_core.h>

#define TAMA_DATA 0x10000
#define TAMA_FRAMEBUFFER 0x20000
#define TAMA_FRAME_SIZE (32 * 16 * 3)
#define TAMA_SCREEN_BUFFER 0x21000
#define TAMA_SCREEN_WIDTH 128
#define TAMA_SCREEN_HEIGHT 96
#define TAMA_SCREEN_SIZE (TAMA_SCREEN_WIDTH * TAMA_SCREEN_HEIGHT * 3)
#define TAMA_AUDIO_BUFFER 0x30000
#define TAMA_AUDIO_SIZE 32768
#define TAMA_HZ 32768

typedef struct {
	RCore *core;
	RIO *io;
	REsilCallbacks callbacks;
	bool (*previous_cmd)(REsil *, const char *, ut64, ut64);
	char *previous_step, *previous_step_out;
	bool previous_va, previous_skipself;
	ut32 bank, previous_bank, maps[8];
	int map_count, source_fd, rom_fd, data_fd, frame_fd, audio_fd, screen_fd;
	ut8 hw[128], keys, lcd[160], icons;
	ut8 timer_data, timer_reload;
	ut32 clock_ticks, timer_ticks, stopwatch_ticks, stopwatch_count;
	ut64 cycles, ticks, steps, interrupts;
	ut32 sample_clock, sound_phase, scaled_cycles;
	ut8 audio_pending[1024];
	ut32 audio_pending_size;
	ut64 audio_produced, audio_consumed;
	bool audio_playing, muted, failed;
	char *expressions[8192];
	ut16 opcodes[8192];
	ut8 instruction_cycles[8192];
} RCoreTama;

typedef struct { const char *name; ut16 address; } TamaRegister;
static const TamaRegister hw_registers[] = {
	{ "IT", 0xf00 }, { "ISW", 0xf01 }, { "IPT", 0xf02 }, { "ISIO", 0xf03 },
	{ "IK0", 0xf04 }, { "IK1", 0xf05 },
	{ "EIT", 0xf10 }, { "EISW", 0xf11 }, { "EIPT", 0xf12 }, { "EISIO", 0xf13 },
	{ "EIK0", 0xf14 }, { "EIK1", 0xf15 },
	{ "TM0", 0xf20 }, { "TM1", 0xf21 }, { "SWL", 0xf22 }, { "SWH", 0xf23 },
	{ "PTL", 0xf24 }, { "PTH", 0xf25 }, { "RDPTL", 0xf26 }, { "RDPTH", 0xf27 },
	{ "SD0", 0xf30 }, { "SD1", 0xf31 },
	{ "K0", 0xf40 }, { "DFK0", 0xf41 }, { "K1", 0xf42 },
	{ "R0", 0xf50 }, { "R1", 0xf51 }, { "R2", 0xf52 }, { "R3", 0xf53 }, { "R4", 0xf54 },
	{ "P0", 0xf60 }, { "P1", 0xf61 }, { "P2", 0xf62 }, { "P3", 0xf63 },
	{ "CLKCHG", 0xf70 }, { "LCDCTL", 0xf71 }, { "LC", 0xf72 }, { "SVD", 0xf73 },
	{ "BZFQ", 0xf74 }, { "BZCTL", 0xf75 }, { "TMRST", 0xf76 }, { "SWCTL", 0xf77 },
	{ "PTCTL", 0xf78 }, { "PTCLK", 0xf79 }, { "SIOCTL", 0xf7a },
	{ "HZ", 0xf7b }, { "IOC", 0xf7d }, { "PUP", 0xf7e }
};

static RCoreTama *tama_get(REsil *esil) {
	RListIter *iter;
	REsilActivePlugin *active;
	r_list_foreach (esil->active_plugins, iter, active) {
		if (!strcmp (active->plugin->meta.name, "tamagotchi")) {
			return active->user;
		}
	}
	return NULL;
}

static ut64 tama_reg(RCoreTama *tama, const char *name) {
	ut64 value = 0;
	REsil *esil = &tama->core->esil.esil;
	esil->reg_if.reg_read (esil->reg_if.reg, name, &value);
	return value;
}

static void tama_set_reg(RCoreTama *tama, const char *name, ut64 value) {
	REsil *esil = &tama->core->esil.esil;
	esil->reg_if.reg_write (esil->reg_if.reg, name, value);
}

static void tama_hw_set(RCoreTama *tama, unsigned offset, ut8 value) {
	tama->hw[offset] = value & 15;
	r_io_fd_write_at (tama->io, tama->data_fd, 0xf00 + offset, tama->hw + offset, 1);
}

static void tama_factor(RCoreTama *tama, unsigned slot, ut8 bits) {
	tama_hw_set (tama, slot, tama->hw[slot] | bits);
}

static void tama_keys(RCoreTama *tama, ut8 keys) {
	ut8 pins = 15 ^ (((keys & 1) << 2) | (keys & 2) | ((keys & 4) >> 2) | (keys & 8));
	ut8 mask = tama->hw[0x14];
	ut8 relation = tama->hw[0x41];
	ut8 before = (tama->hw[0x40] ^ relation) & mask;
	ut8 after = (pins ^ relation) & mask;
	if (!before && after) {
		tama_factor (tama, 4, 1);
	}
	tama_hw_set (tama, 0x40, pins);
	tama->keys = keys & 15;
}

#include "screen.inc.c"

static void tama_render(RCoreTama *tama) {
	static const ut8 segments[40] = {
		0, 1, 2, 3, 4, 5, 6, 7, 32, 8, 9, 10, 11, 12, 13, 14, 15, 33, 34, 35,
		31, 30, 29, 28, 27, 26, 25, 24, 36, 23, 22, 21, 20, 19, 18, 17, 16, 37, 38, 39
	};
	ut8 pixels[TAMA_FRAME_SIZE];
	memset (pixels, 0, sizeof (pixels));
	tama->icons = 0;
	int n, bit;
	for (n = 0; n < 160; n++) {
		int seg = (n % 80) / 2;
		int com = (n / 80) * 8 + (n & 1) * 4;
		for (bit = 0; bit < 4; bit++) {
			bool on = (tama->lcd[n] >> bit) & 1;
			if (tama->hw[0x71] & 4) {
				on = true;
			} else if (tama->hw[0x71] & 8) {
				on = false;
			}
			if (segments[seg] < 32) {
				ut8 *pixel = pixels + ((com + bit) * 32 + segments[seg]) * 3;
				// RGB white is an active LCD dot, matching pri's monochrome view.
				memset (pixel, on? 255: 0, 3);
			} else if (on && seg == 8 && com + bit < 4) {
				tama->icons |= 1 << (com + bit);
			} else if (on && seg == 28 && com + bit >= 12) {
				tama->icons |= 1 << (com + bit - 8);
			}
		}
	}
	r_io_fd_write_at (tama->io, tama->frame_fd, 0, pixels, sizeof (pixels));
	r_io_fd_write_at (tama->io, tama->frame_fd, sizeof (pixels), &tama->icons, 1);
	tama_screen_render (tama, pixels);
}

static bool tama_data_valid(unsigned addr) {
	return addr < 0x280 || (addr >= 0xe00 && addr < 0xe50) || (addr >= 0xe80 && addr < 0xed0) || (addr >= 0xf00 && addr < 0xf80);
}

static ut8 tama_data_read(RCoreTama *tama, unsigned addr) {
	if (!tama_data_valid (addr)) {
		return 0;
	}
	ut8 value = 0;
	if (addr >= 0xf00) {
		unsigned offset = addr - 0xf00;
		value = tama->hw[offset];
		if (offset < 6) {
			tama_hw_set (tama, offset, 0);
		} else if (offset == 0x73) {
			value &= 7;
		}
	} else {
		r_io_fd_read_at (tama->io, tama->data_fd, addr, &value, 1);
	}
	return value & 15;
}

static void tama_data_write(RCoreTama *tama, unsigned addr, ut8 value) {
	value &= 15;
	if (!tama_data_valid (addr)) {
		return;
	}
	if (addr < 0xf00) {
		r_io_fd_write_at (tama->io, tama->data_fd, addr, &value, 1);
		if (addr >= 0xe00) {
			tama->lcd[(addr & 0x7f) + ((addr & 0x80)? 80: 0)] = value;
			tama_render (tama);
		}
		return;
	}
	unsigned off = addr - 0xf00;
	if (off < 6 || (off >= 0x20 && off <= 0x25) || off == 0x40 || off == 0x42) {
		return;
	}
	switch (off) {
	case 0x11: value &= 3; break;
	case 0x12: case 0x13: value &= 1; break;
	case 0x75: value &= 3; break;
	case 0x26: tama->timer_reload = (tama->timer_reload & 0xf0) | value; break;
	case 0x27: tama->timer_reload = (tama->timer_reload & 15) | (value << 4); break;
	case 0x76:
		if (value & 2) {
			tama->clock_ticks = 0;
			tama_hw_set (tama, 0x20, 0);
			tama_hw_set (tama, 0x21, 0);
		}
		value = 0;
		break;
	case 0x77:
		if (value & 2) {
			tama->stopwatch_count = tama->stopwatch_ticks = 0;
			tama_hw_set (tama, 0x22, 0);
			tama_hw_set (tama, 0x23, 0);
		}
		value &= 1;
		break;
	case 0x78:
		if (value & 2) {
			tama->timer_data = tama->timer_reload;
		}
		if ((value & 1) && !(tama->hw[0x78] & 1)) {
			tama->timer_ticks = 0;
		}
		value &= 1;
		tama_hw_set (tama, 0x24, tama->timer_data & 15);
		tama_hw_set (tama, 0x25, tama->timer_data >> 4);
		break;
	}
	tama_hw_set (tama, off, value);
	if (off == 0x71) {
		tama_render (tama);
	}
}

static bool tama_mem_read(REsil *esil, ut64 addr, ut8 *buf, int len) {
	RCoreTama *tama = esil->cb.user;
	int i;
	if (addr >= TAMA_DATA && addr < TAMA_DATA + 4096) {
		for (i = 0; i < len; i++) {
			buf[i] = addr + i < TAMA_DATA + 4096? tama_data_read (tama, addr + i - TAMA_DATA): 0;
		}
		return true;
	}
	return r_io_read_at (tama->io, addr, buf, len);
}

static bool tama_mem_write(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	RCoreTama *tama = esil->cb.user;
	if (addr >= TAMA_DATA && addr < TAMA_DATA + 4096) {
		int i;
		for (i = 0; i < len && addr + i < TAMA_DATA + 4096; i++) {
			tama_data_write (tama, addr + i - TAMA_DATA, buf[i]);
		}
	}
	return true;
}

#include "audio.inc.c"

static void tama_tick(RCoreTama *tama, unsigned cycles) {
	tama->cycles += cycles;
	while (cycles--) {
		// OSC1 continues to clock the timers when the CPU selects OSC3.
		tama->scaled_cycles += (tama->hw[0x70] & 8)? TAMA_HZ: 1000000;
		if (tama->scaled_cycles < 1000000) {
			continue;
		}
		tama->scaled_cycles -= 1000000;
		tama->ticks++;
		unsigned old = tama->clock_ticks++;
		unsigned now = tama->clock_ticks;
		unsigned falling = old & ~now;
		if ((old ^ now) & 0x7f80) {
			tama_hw_set (tama, 0x20, (now >> 7) & 15);
			tama_hw_set (tama, 0x21, (now >> 11) & 15);
		}
		ut8 factors = ((falling >> 11) & 8) | ((falling >> 11) & 4) | ((falling >> 10) & 2) | ((falling >> 9) & 1);
		if (factors) {
			tama_factor (tama, 0, factors);
		}
		if (tama->hw[0x78] & 1) {
			unsigned select = tama->hw[0x79] & 7;
			unsigned period = select >= 2? 128U >> (select - 2): 0;
			if (period && ++tama->timer_ticks >= period) {
				tama->timer_ticks = 0;
				if (!--tama->timer_data) {
					tama->timer_data = tama->timer_reload;
					tama_factor (tama, 2, 1);
				}
				tama_hw_set (tama, 0x24, tama->timer_data & 15);
				tama_hw_set (tama, 0x25, tama->timer_data >> 4);
			}
		}
		if (tama->hw[0x77] & 1) {
			tama->stopwatch_ticks += 100;
			if (tama->stopwatch_ticks >= TAMA_HZ) {
				tama->stopwatch_ticks -= TAMA_HZ;
				tama->stopwatch_count = (tama->stopwatch_count + 1) % 100;
				tama_hw_set (tama, 0x22, tama->stopwatch_count % 10);
				tama_hw_set (tama, 0x23, tama->stopwatch_count / 10);
				tama_factor (tama, 1, (tama->stopwatch_count % 10 == 0)? (tama->stopwatch_count? 1: 3): 0);
			}
		}
		tama->sample_clock += 44100;
		while (tama->sample_clock >= TAMA_HZ) {
			tama->sample_clock -= TAMA_HZ;
			static const unsigned divisors[] = { 8, 10, 12, 14, 16, 20, 24, 28 };
			unsigned divisor = divisors[tama->hw[0x74] & 7];
			tama->sound_phase = (tama->sound_phase + TAMA_HZ) % (44100 * divisor);
			int sample = (tama->hw[0x54] & 8)? 0: tama->sound_phase < 44100 * divisor / 2? 6000: -6000;
			r_write_le16 (tama->audio_pending + tama->audio_pending_size, sample);
			r_write_le16 (tama->audio_pending + tama->audio_pending_size + 2, sample);
			tama->audio_pending_size += 4;
			if (tama->audio_pending_size == sizeof (tama->audio_pending)) {
				tama_audio_flush (tama);
			}
		}
	}
}

static void tama_interrupt(RCoreTama *tama) {
	static const int priority[] = { 2, 3, 5, 4, 1, 0 };
	static const int vectors[] = { 2, 4, 12, 10, 6, 8 };
	if (!tama_reg (tama, "I")) {
		return;
	}
	int i;
	for (i = 0; i < 6; i++) {
		int slot = priority[i];
		bool pending = slot == 4 || slot == 5? tama->hw[slot] && tama->hw[0x10 + slot]: (tama->hw[slot] & tama->hw[0x10 + slot]) != 0;
		if (!pending) {
			continue;
		}
		ut16 pc = tama_reg (tama, "pc") >> 1;
		ut8 sp = tama_reg (tama, "sp");
		tama_data_write (tama, --sp, (pc >> 8) & 15);
		tama_data_write (tama, --sp, (pc >> 4) & 15);
		tama_data_write (tama, --sp, pc & 15);
		tama_set_reg (tama, "sp", sp);
		tama_set_reg (tama, "I", 0);
		tama_set_reg (tama, "halted", 0);
		tama_set_reg (tama, "pc", ((pc & 0x1000) | 0x100 | vectors[slot]) << 1);
		tama_set_reg (tama, "np", (pc >> 8 & 0x10) | 1);
		tama->interrupts++;
		tama_tick (tama, 12);
		return;
	}
}

static bool tama_step(RCoreTama *tama) {
	REsil *esil = &tama->core->esil.esil;
	ut16 pc = tama_reg (tama, "pc");
	if (tama->failed) {
		return false;
	}
	tama->steps++;
	if (tama_reg (tama, "halted")) {
		tama_tick (tama, 5);
		tama_interrupt (tama);
		return true;
	}
	ut8 bytes[2];
	if ((pc & 1) || pc >= 0x3000 || r_io_fd_read_at (tama->io, tama->rom_fd, pc, bytes, 2) != 2) {
		R_LOG_ERROR ("Invalid Tamagotchi instruction address 0x%04x", pc);
		tama->failed = true;
		return false;
	}
	ut16 word = r_read_le16 (bytes);
	unsigned index = pc / 2;
	if (!tama->expressions[index] || tama->opcodes[index] != word) {
		RAnalOp op;
		r_anal_op_init (&op);
		r_anal_op_set_bytes (&op, pc, bytes, 2);
		if (!r_arch_session_decode (tama->core->anal->arch->session, &op, R_ARCH_OP_MASK_ESIL)) {
			r_anal_op_fini (&op);
			R_LOG_ERROR ("Invalid E0C62 instruction 0x%03x at 0x%04x", word, pc);
			tama->failed = true;
			return false;
		}
		free (tama->expressions[index]);
		tama->expressions[index] = r_strbuf_drain_nofree (&op.esil);
		tama->opcodes[index] = word;
		tama->instruction_cycles[index] = op.cycles;
		r_anal_op_fini (&op);
	}
	tama_set_reg (tama, "pc", (pc + 2) & 0x3fff);
	esil->addr = pc;
	esil->trap = 0;
	bool previous_in_step = esil->in_cmd_step;
	esil->in_cmd_step = true;
	const char *expression = tama->expressions[index];
	bool ok = !*expression || r_esil_parse (esil, expression);
	esil->in_cmd_step = previous_in_step;
	r_esil_stack_free (esil);
	if (!ok || esil->trap) {
		R_LOG_ERROR ("E0C62 ESIL failed at 0x%04x: %s", pc, tama->expressions[index]);
		tama->failed = true;
		return false;
	}
	tama_tick (tama, tama->instruction_cycles[index]);
	if ((word & 0xfe0) != 0xe40 && word != 0xf48) {
		tama_interrupt (tama);
	}
	return true;
}

static bool tama_command(REsil *esil, const char *cmd, ut64 addr, ut64 value) {
	RCoreTama *tama = esil->cb.user;
	if (!strcmp (cmd, "tamagotchi.step")) {
		tama_set_reg (tama, "pc", addr);
		tama_step (tama);
		return true;
	}
	if (!strcmp (cmd, "tamagotchi.tick")) {
		return false;
	}
	if (tama->previous_cmd) {
		return tama->previous_cmd (esil, cmd, addr, value);
	}
	r_core_cmdf (tama->core, "%s 0x%"PFMT64x" 0x%"PFMT64x, cmd, addr, value);
	return tama->core->num->value;
}

static void tama_flags(RCoreTama *tama, bool add) {
	RFlag *flags = tama->core->flags;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (hw_registers); i++) {
		char name[64];
		snprintf (name, sizeof (name), "tama.hw.%s", hw_registers[i].name);
		if (add) {
			r_flag_set (flags, name, TAMA_DATA + hw_registers[i].address, 1);
		} else {
			r_flag_unset_name (flags, name);
		}
	}
	static const struct { const char *name; ut64 addr, size; } regions[] = {
		{ "tama.rom", 0, 0x3000 }, { "tama.ram", TAMA_DATA, 0x280 },
		{ "tama.lcd0", TAMA_DATA + 0xe00, 80 }, { "tama.lcd1", TAMA_DATA + 0xe80, 80 },
		{ "tama.framebuffer", TAMA_FRAMEBUFFER, TAMA_FRAME_SIZE },
		{ "tama.screen", TAMA_SCREEN_BUFFER, TAMA_SCREEN_SIZE },
		{ "tama.icons", TAMA_FRAMEBUFFER + TAMA_FRAME_SIZE, 1 }, { "tama.audio", TAMA_AUDIO_BUFFER, TAMA_AUDIO_SIZE }
	};
	for (i = 0; i < R_ARRAY_SIZE (regions); i++) {
		if (add) {
			r_flag_set (flags, regions[i].name, regions[i].addr, regions[i].size);
		} else {
			r_flag_unset_name (flags, regions[i].name);
		}
	}
}

static void tama_fini(REsil *esil, void *user) {
	RCoreTama *tama = user;
	tama_audio_stop (tama);
	esil->cb = tama->callbacks;
	esil->cmd = tama->previous_cmd;
	if (tama->previous_step) {
		r_config_set (tama->core->config, "cmd.esil.step", tama->previous_step);
		r_config_set (tama->core->config, "cmd.esil.stepout", tama->previous_step_out);
	}
	free (tama->previous_step);
	free (tama->previous_step_out);
	if (tama->bank != UT32_MAX) {
		r_io_bank_use (tama->io, tama->previous_bank);
		r_io_bank_del (tama->io, tama->bank);
	}
	r_config_set_b (tama->core->config, "io.va", tama->previous_va);
	r_config_set_b (tama->core->config, "esil.skipself", tama->previous_skipself);
	int i;
	for (i = 0; i < tama->map_count; i++) {
		r_io_map_del (tama->io, tama->maps[i]);
	}
	int fds[] = { tama->rom_fd, tama->data_fd, tama->frame_fd, tama->audio_fd, tama->screen_fd };
	for (i = 0; i < R_ARRAY_SIZE (fds); i++) {
		if (fds[i] >= 0) {
			r_io_fd_close (tama->io, fds[i]);
		}
	}
	for (i = 0; i < R_ARRAY_SIZE (tama->expressions); i++) {
		free (tama->expressions[i]);
	}
	tama_flags (tama, false);
	free (tama);
}

static void *tama_plugin_init(REsil *esil) {
	RCoreTama *tama = R_NEW0 (RCoreTama);
	tama->core = esil->anal->coreb.core;
	tama->io = esil->anal->iob.io;
	tama->callbacks = esil->cb;
	tama->previous_cmd = esil->cmd;
	tama->previous_bank = tama->io->bank;
	tama->previous_va = tama->io->va;
	tama->previous_skipself = r_config_get_b (tama->core->config, "esil.skipself");
	tama->bank = UT32_MAX;
	tama->rom_fd = tama->data_fd = tama->frame_fd = tama->audio_fd = tama->screen_fd = -1;
	return tama;
}

static REsilPlugin tama_plugin = {
	.meta = { .name = "tamagotchi", .desc = "Tamagotchi ESIL hardware", .license = "LGPL-3.0-only" },
	.init = tama_plugin_init,
	.fini = tama_fini,
};

static bool tama_map(RCoreTama *tama, int fd, int perm, ut64 delta, ut64 addr, ut64 size, const char *name) {
	RIOMap *map = r_io_map_add (tama->io, fd, perm, delta, addr, size);
	if (!map) {
		return false;
	}
	r_io_map_set_name (map, name);
	tama->maps[tama->map_count++] = map->id;
	return true;
}

static int tama_malloc(RCoreTama *tama, unsigned size) {
	char uri[64];
	snprintf (uri, sizeof (uri), "malloc://%u", size);
	RIODesc *desc = r_io_open_nomap (tama->io, uri, R_PERM_RW, 0);
	return desc? desc->fd: -1;
}

static bool tama_init(RCore *core) {
	REsil *esil = &core->esil.esil;
	RCoreTama *previous = tama_get (esil);
	RBinFile *bf = r_bin_cur (core->bin);
	int fd = previous? previous->source_fd: bf? bf->fd: r_io_fd_get_current (core->io);
	if (r_io_fd_size (core->io, fd) != 0x3000) {
		R_LOG_ERROR ("Expected a P1/P2 ROM: 6144 little-endian 12-bit words (12288 bytes)");
		return false;
	}
	ut8 rom[0x3000];
	if (r_io_fd_read_at (core->io, fd, 0, rom, sizeof (rom)) != sizeof (rom)) {
		return false;
	}
	unsigned i;
	for (i = 0; i < sizeof (rom); i += 2) {
		if (r_read_le16 (rom + i) > 0xfff) {
			R_LOG_ERROR ("Invalid 12-bit ROM word at byte 0x%x", i);
			return false;
		}
	}
	r_esil_plugin_deactivate (esil, "tamagotchi");
	if (!r_config_set (core->config, "asm.arch", "e0c62")) {
		R_LOG_ERROR ("Rebuild radare2 with the E0C62 architecture first");
		return false;
	}
	r_config_set_i (core->config, "asm.bits", 16);
	r_libstore_add (esil->libstore, &tama_plugin);
	if (!r_esil_plugin_activate (esil, "tamagotchi")) {
		return false;
	}
	RCoreTama *tama = tama_get (esil);
	tama->source_fd = fd;
	RIOBank *bank = r_io_bank_new ("tamagotchi");
	if (!bank || !r_io_bank_add (core->io, bank)) {
		r_io_bank_free (bank);
		goto fail;
	}
	tama->bank = bank->id;
	r_io_bank_use (core->io, tama->bank);
	r_config_set_b (core->config, "io.va", true);
	r_config_set_b (core->config, "esil.skipself", false);
	tama->rom_fd = tama_malloc (tama, sizeof (rom));
	tama->data_fd = tama_malloc (tama, 4096);
	tama->frame_fd = tama_malloc (tama, TAMA_FRAME_SIZE + 1);
	tama->audio_fd = tama_malloc (tama, TAMA_AUDIO_SIZE);
	tama->screen_fd = tama_malloc (tama, TAMA_SCREEN_SIZE);
	if (tama->rom_fd < 0 || tama->data_fd < 0 || tama->frame_fd < 0 || tama->audio_fd < 0 || tama->screen_fd < 0) {
		goto fail;
	}
	r_io_fd_write_at (core->io, tama->rom_fd, 0, rom, sizeof (rom));
	if (!tama_map (tama, tama->rom_fd, R_PERM_RX, 0, 0, sizeof (rom), "tama.rom")
			|| !tama_map (tama, tama->data_fd, R_PERM_RW, 0, TAMA_DATA, 0x280, "tama.ram")
			|| !tama_map (tama, tama->data_fd, R_PERM_RW, 0xe00, TAMA_DATA + 0xe00, 80, "tama.lcd0")
			|| !tama_map (tama, tama->data_fd, R_PERM_RW, 0xe80, TAMA_DATA + 0xe80, 80, "tama.lcd1")
			|| !tama_map (tama, tama->data_fd, R_PERM_RW, 0xf00, TAMA_DATA + 0xf00, 128, "tama.hw")
			|| !tama_map (tama, tama->frame_fd, R_PERM_RW, 0, TAMA_FRAMEBUFFER, TAMA_FRAME_SIZE + 1, "tama.framebuffer")
			|| !tama_map (tama, tama->screen_fd, R_PERM_RW, 0, TAMA_SCREEN_BUFFER, TAMA_SCREEN_SIZE, "tama.screen")
			|| !tama_map (tama, tama->audio_fd, R_PERM_RW, 0, TAMA_AUDIO_BUFFER, TAMA_AUDIO_SIZE, "tama.audio")) {
		goto fail;
	}
	r_reg_arena_zero (core->anal->reg);
	tama_set_reg (tama, "pc", 0x200);
	tama_set_reg (tama, "np", 1);
	tama_hw_set (tama, 0x54, 15);
	tama_hw_set (tama, 0x71, 8);
	tama_hw_set (tama, 0x41, 15);
	tama_hw_set (tama, 0x40, 15);
	tama_hw_set (tama, 0x42, 15);
	esil->cb.user = tama;
	esil->cb.hook_mem_read = tama_mem_read;
	esil->cb.hook_mem_write = tama_mem_write;
	tama->previous_step = strdup (r_config_get (core->config, "cmd.esil.step"));
	tama->previous_step_out = strdup (r_config_get (core->config, "cmd.esil.stepout"));
	r_config_set (core->config, "cmd.esil.step", "tamagotchi.step");
	r_config_set (core->config, "cmd.esil.stepout", "tamagotchi.tick");
	esil->cmd = tama_command;
	tama_flags (tama, true);
	tama_render (tama);
	return true;
fail:
	r_esil_plugin_deactivate (esil, "tamagotchi");
	return false;
}

#include "input.inc.c"

static void tama_visual_draw(RCoreTama *tama, const TamaInput *input) {
	RCons *cons = tama->core->cons;
	int rows;
	int cols = r_cons_get_size (cons, &rows);
	char *screen = tama_screen_fit (tama, R_MAX (1, cols), R_MAX (1, rows - 4));
	r_cons_gotoxy (cons, 0, 0);
	r_cons_print (cons, "r2tama  A=a B=s C=d  m=mute  q=quit\x1b[K\n");
	r_cons_print (cons, screen);
	r_cons_printf (cons, "\x1b[Kicons=%02x pc=%04"PFMT64x" time=%.2fs mute=%s\n\x1b[Kinput=%s (%"PFMT64u" ms)\n",
		tama->icons, tama_reg (tama, "pc"), (double)tama->ticks / TAMA_HZ, tama->muted? "on": "off",
		input->event_types? "press/release": "timed", input->hold_us / 1000);
	r_cons_visual_flush (cons);
	free (screen);
}

static void tama_visual(RCoreTama *tama, ut32 hold_ms) {
	RCore *core = tama->core;
	RCons *cons = core->cons;
	if (!r_cons_is_interactive (cons)) {
		R_LOG_ERROR ("Tamagotchi play mode requires scr.interactive=true");
		return;
	}
	tama_audio_flush (tama);
	tama->audio_consumed = tama->audio_produced;
	bool muted = tama->muted;
	bool audio = tama_audio_start (tama);
	bool previous_vmode = core->vmode;
	bool mouse = cons->mouse;
	ut64 backsteps = r_config_get_i (core->config, "esil.maxbacksteps");
	r_config_set_i (core->config, "esil.maxbacksteps", 0);
	core->vmode = true;
	tama_keys (tama, 0);
	r_io_bank_use (tama->io, tama->bank);
	r_cons_enable_mouse (cons, false);
	bool cup = !previous_vmode && r_cons_set_cup (true);
	r_cons_set_raw (cons, true);
	r_cons_show_cursor (cons, false);
	r_cons_print (cons, "\x1b[>11u\x1b[?u");
	r_cons_flush (cons);
	r_cons_clear (cons);
	r_cons_break_push (cons, NULL, NULL);
	TamaInput input = { .hold_us = (ut64)hold_ms * 1000 };
	ut64 start = r_time_now_mono ();
	ut64 start_ticks = tama->ticks;
	ut64 next_render = 0;
	while (!r_cons_is_breaked (cons) && tama_visual_input (tama, &input)) {
		if (muted != tama->muted) {
			muted = tama->muted;
			audio = !muted && tama_audio_start (tama);
		}
		if (audio) {
			tama_audio_submit (tama, false);
		}
		ut64 now = r_time_now_mono ();
		if (now >= next_render) {
			tama_visual_draw (tama, &input);
			next_render = now + 33333;
		}
		ut64 target = (now - start + 20000) * TAMA_HZ / 1000000;
		if (tama->ticks - start_ticks >= target) {
			r_sys_usleep (1000);
			continue;
		}
		int i;
		for (i = 0; i < 128 && tama->ticks - start_ticks < target; i++) {
			if (!tama_step (tama)) {
				goto done;
			}
		}
	}
done:
	r_cons_break_pop (cons);
	tama_audio_stop (tama);
	tama_audio_flush (tama);
	tama_keys (tama, 0);
	r_cons_print (cons, "\x1b[<u");
	r_cons_flush (cons);
	r_cons_set_raw (cons, previous_vmode);
	r_cons_show_cursor (cons, true);
	if (cup) {
		r_cons_set_cup (false);
	}
	r_cons_enable_mouse (cons, mouse);
	core->vmode = previous_vmode;
	r_config_set_i (core->config, "esil.maxbacksteps", backsteps);
}

static char *tama_cmd(RCore *core, const char *command) {
	const char *input = r_str_trim_head_ro (command);
	REsil *esil = &core->esil.esil;
	if (*input == '?') {
		return strdup (
			"| r2tama                initialize/reset P1/P2 hardware and E0C62 ESIL\n"
			"| r2tama-               release hardware, maps, flags and hooks\n"
			"| r2tama play [hold-ms]  boot/play: a=A s=B d=C m=mute q=quit (default hold 500 ms)\n"
			"| r2tama screen         render the LCD matrix and eight fixed pictograms\n"
			"| r2tama keys N         held buttons: A=1 B=2 C=4 tap=8 (0 releases)\n"
			"| r2tama status         CPU clocks, OSC1 ticks, PC, interrupts, icons, PCM\n"
			"| r2tama maps           list hardware mappings\n"
			"| r2tama regs           list named hardware registers and values\n"
			"| r2tama audio          queue PCM through r2au (audio- stops)\n"
			"| aes [N]               execute CPU and hardware together\n"
			"| e hex.cols=128; pri @tama.screen!36864\n"
			"| e hex.cols=32; pri @tama.framebuffer!1536  (matrix only)\n");
	}
	if (!*input) {
		tama_init (core);
		return NULL;
	}
	RCoreTama *tama = tama_get (esil);
	if (!tama && (!strcmp (input, "play") || r_str_startswith (input, "play "))) {
		if (!tama_init (core)) {
			return NULL;
		}
		tama = tama_get (esil);
	}
	if (!tama) {
		R_LOG_ERROR ("Initialize with r2tama first");
		return NULL;
	}
	tama_audio_flush (tama);
	if (!strcmp (input, "-")) {
		r_esil_plugin_deactivate (esil, "tamagotchi");
	} else if (r_str_startswith (input, "keys ")) {
		tama_keys (tama, r_num_math (core->num, input + 5));
	} else if (!strcmp (input, "status")) {
		return r_str_newf ("cycles=%"PFMT64u" ticks=%"PFMT64u" steps=%"PFMT64u" pc=0x%04"PFMT64x" halted=%"PFMT64u" interrupts=%"PFMT64u" icons=0x%02x keys=%u audio=%"PFMT64u" offset=%"PFMT64u" muted=%d failed=%d\n",
			tama->cycles, tama->ticks, tama->steps, tama_reg (tama, "pc"), tama_reg (tama, "halted"), tama->interrupts, tama->icons, tama->keys, tama->audio_produced, tama->audio_produced % TAMA_AUDIO_SIZE, tama->muted, tama->failed);
	} else if (!strcmp (input, "screen")) {
		return tama_screen (tama);
	} else if (!strcmp (input, "regs")) {
		RStrBuf out;
		r_strbuf_init (&out);
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (hw_registers); i++) {
			r_strbuf_appendf (&out, "0x%05x tama.hw.%-8s %x\n", TAMA_DATA + hw_registers[i].address, hw_registers[i].name, tama->hw[hw_registers[i].address - 0xf00]);
		}
		return r_strbuf_drain_nofree (&out);
	} else if (!strcmp (input, "maps")) {
		RStrBuf out;
		r_strbuf_initf (&out, "bank=%u\n", tama->bank);
		int i;
		for (i = 0; i < tama->map_count; i++) {
			RIOMap *map = r_io_map_get (tama->io, tama->maps[i]);
			if (map) {
				r_strbuf_appendf (&out, "0x%05"PFMT64x"-0x%05"PFMT64x" %s %s\n", r_io_map_begin (map), r_io_map_end (map) - 1, r_str_perm (map->perm, false), map->name);
			}
		}
		return r_strbuf_drain_nofree (&out);
	} else if (!strcmp (input, "audio")) {
		if (tama_audio_start (tama)) {
			while (tama->audio_consumed < tama->audio_produced && tama_audio_submit (tama, true)) {
			}
		}
	} else if (!strcmp (input, "audio-")) {
		tama_audio_stop (tama);
	} else if (!strcmp (input, "play") || r_str_startswith (input, "play ")) {
		ut64 hold_ms = input[4]? r_num_math (core->num, input + 5): 500;
		if (hold_ms < 1 || hold_ms > 5000) {
			R_LOG_ERROR ("Key hold must be between 1 and 5000 ms");
		} else {
			tama_visual (tama, hold_ms);
		}
	} else {
		R_LOG_ERROR ("Unknown Tamagotchi command (r2tama?)");
	}
	return NULL;
}

static RCmdResult tama_call(RCmdContext *ctx) {
	char *output = tama_cmd (ctx->user, ctx->subcmd.a);
	if (R_STR_ISNOTEMPTY (output)) {
		r_cons_print (ctx->cons, output);
		if (output[strlen (output) - 1] != '\n') {
			r_cons_newline (ctx->cons);
		}
	}
	free (output);
	return (RCmdResult) { 0 };
}

static bool tama_core_fini(RCorePluginSession *session) {
	REsil *esil = &session->core->esil.esil;
	if (esil->libstore) {
		r_esil_plugin_del (esil, "tamagotchi");
	}
	return true;
}

RCorePlugin r_core_plugin_tama = {
	.meta = { .name = "r2tama", .desc = "Tamagotchi E0C62 ESIL hardware, LCD, buttons and speaker", .license = "LGPL-3.0-only" },
	.command = "r2tama",
	.call_ctx = tama_call,
	.fini = tama_core_fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_tama,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
