/* radare2 - LGPL - Copyright 2026 - pancake */

#include <r_core.h>
#include "instructions.inc.c"
#include "registers.inc.c"

#define GG_FRAMEBUFFER 0x10000
#define GG_FRAME_SIZE (160 * 144 * 3)
#define GG_AUDIO_BUFFER 0x30000
#define GG_AUDIO_SIZE 32768
#define GG_PORT_BASE 0x1000000
#define GG_AUDIO_LEAD_US 100000
#define GG_AUDIO_PRIME_BYTES 16384

typedef struct {
	RCore *core;
	RIO *io;
	REsilCallbacks callbacks;
	bool (*previous_cmd)(REsil *, const char *, ut64, ut64);
	char *previous_step, *previous_step_out;
	bool previous_va, previous_skipself;
	ut32 bank, previous_bank, maps[10];
	int map_count, cart_fd, rom_fd, ram_fd, frame_fd, audio_fd;
	ut32 slots[3], rom_banks;
	ut8 mapper[4], keys, ports[7];
	ut8 vram[0x4000], cram[64], vdp[16];
	ut16 address;
	ut8 code, latch, read_buffer, status, line_counter;
	bool pending, line_irq;
	ut32 dots, line;
	ut64 cycles, frames;
	GameGearInstruction *instructions;
	ut16 tone[3], timer[4], noise;
	ut8 volume[4], output[4], sound_latch, noise_control, stereo, psg_divider;
	ut32 sample_clock;
	ut8 audio_pending[1024];
	ut32 audio_pending_size;
	ut64 audio_produced, audio_consumed;
	bool audio_playing;
} RCoreGameGear;

static RCoreGameGear *gamegear_get(REsil *esil) {
	RListIter *iter;
	REsilActivePlugin *active;
	r_list_foreach (esil->active_plugins, iter, active) {
		if (!strcmp (active->plugin->meta.name, "gamegear")) {
			return active->user;
		}
	}
	return NULL;
}

static void gamegear_keys(RCoreGameGear *gg, ut8 keys) {
	gg->keys = keys;
}

static void gamegear_banks(RCoreGameGear *gg) {
	int i;
	for (i = 0; i < 3; i++) {
		RIOMap *map = r_io_map_get (gg->io, gg->slots[i]);
		if (i == 2 && (gg->mapper[0] & 8)) {
			map->fd = gg->ram_fd;
			map->perm = R_PERM_RWX;
			map->delta = 0x2000 + ((gg->mapper[0] & 4)? 0x4000: 0);
		} else {
			map->fd = gg->rom_fd;
			map->perm = R_PERM_RX;
			map->delta = (gg->mapper[i + 1] % gg->rom_banks) * 0x4000 + (i == 0? 0x400: 0);
		}
	}
}

static ut8 gamegear_tile(RCoreGameGear *gg, int tile, int x, int y) {
	int at = ((tile & 511) * 32 + y * 4) & 0x3fff;
	int shift = 7 - x;
	return ((gg->vram[at] >> shift) & 1) | (((gg->vram[at + 1] >> shift) & 1) << 1)
		| (((gg->vram[at + 2] >> shift) & 1) << 2) | (((gg->vram[at + 3] >> shift) & 1) << 3);
}

static void gamegear_scanline(RCoreGameGear *gg, int y) {
	ut8 colors[256], priority[256] = {0}, sprites[256] = {0};
	int x, i;
	ut8 backdrop = 16 | (gg->vdp[7] & 15);
	memset (colors, backdrop, sizeof (colors));
	if (gg->vdp[1] & 0x40) {
		int base = (gg->vdp[2] & 14) << 10;
		for (x = 0; x < 256; x++) {
			int sx = (x - ((y < 16 && (gg->vdp[0] & 64))? 0: gg->vdp[8])) & 255;
			int sy = (y + ((x >= 192 && (gg->vdp[0] & 128))? 0: gg->vdp[9])) % 224;
			int at = (base + ((sy / 8) * 32 + sx / 8) * 2) & 0x3fff;
			ut16 entry = r_read_le16 (gg->vram + at);
			int px = sx & 7, py = sy & 7;
			ut8 color = gamegear_tile (gg, entry & 511, (entry & 512)? 7 - px: px, (entry & 1024)? 7 - py: py);
			colors[x] = color | ((entry & 2048)? 16: 0);
			priority[x] = color && (entry & 4096);
		}
		int sat = (gg->vdp[5] & 0x7e) << 7;
		int count = 0;
		int zoom = (gg->vdp[1] & 1)? 2: 1;
		int height = (gg->vdp[1] & 2)? 16: 8;
		for (i = 0; i < 64; i++) {
			int top = gg->vram[sat + i];
			if (top == 208) {
				break;
			}
			top++;
			if (top > 240) {
				top -= 256;
			}
			if (y < top || y >= top + height * zoom) {
				continue;
			}
			if (++count > 8) {
				gg->status |= 0x40;
				break;
			}
			int left = gg->vram[sat + 128 + i * 2] - ((gg->vdp[0] & 8)? 8: 0);
			int tile = gg->vram[sat + 129 + i * 2] | ((gg->vdp[6] & 4)? 256: 0);
			if (height == 16) {
				tile &= ~1;
			}
			int row = (y - top) / zoom;
			for (x = 0; x < 8 * zoom; x++) {
				int px = left + x;
				if (px < 0 || px >= 256) {
					continue;
				}
				ut8 color = gamegear_tile (gg, tile + row / 8, x / zoom, row & 7);
				if (!color) {
					continue;
				}
				if (sprites[px]) {
					gg->status |= 0x20;
					continue;
				}
				sprites[px] = 1;
				if (!priority[px]) {
					colors[px] = 16 | color;
				}
			}
		}
	}
	if (y >= 24 && y < 168) {
		ut8 pixels[160 * 3];
		for (x = 0; x < 160; x++) {
			ut16 color = r_read_le16 (gg->cram + colors[x + 48] * 2);
			pixels[x * 3] = (color & 15) * 17;
			pixels[x * 3 + 1] = ((color >> 4) & 15) * 17;
			pixels[x * 3 + 2] = ((color >> 8) & 15) * 17;
		}
		r_io_fd_write_at (gg->io, gg->frame_fd, (y - 24) * sizeof (pixels), pixels, sizeof (pixels));
	}
}

static void gamegear_sound_write(RCoreGameGear *gg, ut8 value) {
	if (value & 128) {
		gg->sound_latch = (value >> 4) & 7;
	}
	int channel = gg->sound_latch >> 1;
	if (gg->sound_latch & 1) {
		gg->volume[channel] = value & 15;
	} else if (channel == 3) {
		gg->noise_control = value & 7;
		gg->noise = 0x8000;
	} else if (value & 128) {
		gg->tone[channel] = (gg->tone[channel] & 0x3f0) | (value & 15);
	} else {
		gg->tone[channel] = ((value & 63) << 4) | (gg->tone[channel] & 15);
	}
}

static ut8 gamegear_port_read(RCoreGameGear *gg, ut8 port) {
	if (!port) {
		return (gg->keys & 128)? 0x40: 0xc0;
	}
	if (port < 7) {
		return gg->ports[port];
	}
	if (port >= 0x40 && port < 0x80) {
		return (port & 1)? (gg->dots * 3 / 4): gg->line > 218? gg->line - 6: gg->line;
	}
	if (port >= 0x80 && port < 0xc0) {
		gg->pending = false;
		if (port & 1) {
			ut8 status = gg->status;
			gg->status = 0;
			gg->line_irq = false;
			return status;
		}
		ut8 value = gg->read_buffer;
		gg->read_buffer = gg->vram[gg->address];
		gg->address = (gg->address + 1) & 0x3fff;
		return value;
	}
	if (port == 0xdc || port == 0xc0) {
		ut8 keys = gg->keys;
		return 0xff ^ (((keys & 4) >> 2) | ((keys & 8) >> 2) | ((keys & 2) << 1) | ((keys & 1) << 3) | (keys & 0x30));
	}
	return 0xff;
}

static void gamegear_port_write(RCoreGameGear *gg, ut8 port, ut8 value) {
	if (port < 7) {
		gg->ports[port] = value;
		if (port == 6) {
			gg->stereo = value;
		}
	} else if (port >= 0x40 && port < 0x80) {
		gamegear_sound_write (gg, value);
	} else if (port >= 0x80 && port < 0xc0) {
		if (port & 1) {
			if (!gg->pending) {
				gg->latch = value;
				gg->pending = true;
			} else {
				gg->pending = false;
				gg->code = value >> 6;
				gg->address = ((value & 63) << 8) | gg->latch;
				if (gg->code == 2) {
					gg->vdp[value & 15] = gg->latch;
				} else if (!gg->code) {
					gg->read_buffer = gg->vram[gg->address];
					gg->address = (gg->address + 1) & 0x3fff;
				}
			}
		} else {
			gg->pending = false;
			if (gg->code == 3) {
				if (!(gg->address & 1)) {
					gg->latch = value;
				} else {
					gg->cram[(gg->address & 63) - 1] = gg->latch;
					gg->cram[gg->address & 63] = value & 15;
				}
			} else {
				gg->vram[gg->address] = value;
			}
			gg->read_buffer = value;
			gg->address = (gg->address + 1) & 0x3fff;
		}
	}
}

static bool gamegear_mem_read(REsil *esil, ut64 addr, ut8 *buf, int len) {
	RCoreGameGear *gg = esil->cb.user;
	if (addr < GG_PORT_BASE || addr >= GG_PORT_BASE + 0x10000) {
		ut16 at = addr;
		int first = R_MIN (len, 0x10000 - at);
		r_io_bank_read_at (gg->io, gg->bank, at, buf, first);
		if (first < len) {
			r_io_bank_read_at (gg->io, gg->bank, 0, buf + first, len - first);
		}
		return true;
	}
	int i;
	for (i = 0; i < len; i++) {
		buf[i] = gamegear_port_read (gg, addr + i);
	}
	return true;
}

static bool gamegear_mem_write(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	RCoreGameGear *gg = esil->cb.user;
	int i;
	for (i = 0; i < len; i++) {
		if (addr >= GG_PORT_BASE && addr < GG_PORT_BASE + 0x10000) {
			gamegear_port_write (gg, addr + i, buf[i]);
			continue;
		}
		ut16 at = addr + i;
		if (at >= 0xfffc) {
			gg->mapper[at - 0xfffc] = buf[i];
			gamegear_banks (gg);
		}
		if (at >= 0xc000 || (at >= 0x8000 && (gg->mapper[0] & 8))) {
			r_io_bank_write_at (gg->io, gg->bank, at, buf + i, 1);
		}
	}
	return true;
}

static void gamegear_audio_flush(RCoreGameGear *gg) {
	if (!gg->audio_pending_size) {
		return;
	}
	ut32 offset = gg->audio_produced % GG_AUDIO_SIZE;
	ut32 first = R_MIN (gg->audio_pending_size, GG_AUDIO_SIZE - offset);
	r_io_fd_write_at (gg->io, gg->audio_fd, offset, gg->audio_pending, first);
	if (first < gg->audio_pending_size) {
		r_io_fd_write_at (gg->io, gg->audio_fd, 0, gg->audio_pending + first, gg->audio_pending_size - first);
	}
	gg->audio_produced += gg->audio_pending_size;
	gg->audio_pending_size = 0;
}

static void gamegear_audio_stop(RCoreGameGear *gg) {
	if (gg->audio_playing) {
		r_core_call (gg->core, "auq-");
		gg->audio_playing = false;
	}
}

static bool gamegear_audio_start(RCoreGameGear *gg) {
	if (gg->audio_playing) {
		return true;
	}
	RCore *core = gg->core;
	RListIter *iter;
	RCorePluginSession *session;
	bool available = false;
	r_list_foreach (core->rcmd->libstore->plugins, iter, session) {
		if (!strcmp (session->plugin->meta.name, "audio")) {
			available = true;
			break;
		}
	}
	if (!available) {
		R_LOG_WARN ("Audio needs the r2au plugin (r2pm -ci r2au)");
		return false;
	}
	core->num->value = 0;
	char *help = r_core_cmd_str (core, "auq?");
	bool streaming = help && strstr (help, "auqi ");
	free (help);
	if (!streaming) {
		R_LOG_WARN ("Update r2au for asynchronous PCM playback (auq?)");
		return false;
	}
	core->num->value = 0;
	r_core_call (core, "auqi 44100 16 2");
	gg->audio_playing = core->num->value == 1;
	return gg->audio_playing;
}

static bool gamegear_audio_submit(RCoreGameGear *gg, bool partial) {
	gamegear_audio_flush (gg);
	if (gg->audio_produced - gg->audio_consumed > GG_AUDIO_SIZE) {
		gg->audio_consumed = gg->audio_produced - GG_AUDIO_SIZE;
	}
	if (!partial && gg->audio_produced - gg->audio_consumed < 2048) {
		return true;
	}
	ut32 offset = gg->audio_consumed % GG_AUDIO_SIZE;
	ut32 length = R_MIN (gg->audio_produced - gg->audio_consumed, GG_AUDIO_SIZE - offset);
	length = R_MIN (length, 4096);
	if (!length) {
		return true;
	}
	char command[80];
	snprintf (command, sizeof (command), "auq 0x%x %u", GG_AUDIO_BUFFER + offset, length);
	r_core_call (gg->core, command);
	if (gg->core->num->value == length) {
		gg->audio_consumed += length;
		return true;
	}
	return false;
}

static void gamegear_tick(RCoreGameGear *gg, int cycles) {
	static const int amplitude[16] = { 4096, 3254, 2585, 2053, 1631, 1295, 1029, 817, 649, 516, 410, 325, 258, 205, 163, 0 };
	int n, ch;
	for (n = 0; n < cycles; n++) {
		gg->cycles++;
		if (++gg->psg_divider == 16) {
			gg->psg_divider = 0;
			for (ch = 0; ch < 4; ch++) {
				if (gg->timer[ch]) {
					gg->timer[ch]--;
				}
				if (!gg->timer[ch]) {
					if (ch < 3) {
						gg->timer[ch] = gg->tone[ch]? gg->tone[ch]: 0x400;
						gg->output[ch] ^= 1;
					} else {
						gg->timer[ch] = (gg->noise_control & 3) == 3? (gg->tone[2]? gg->tone[2] * 2: 0x800): 0x20 << (gg->noise_control & 3);
						int feedback = (gg->noise_control & 4)? ((gg->noise ^ (gg->noise >> 3)) & 1): gg->noise & 1;
						gg->noise = (gg->noise >> 1) | (feedback << 15);
						gg->output[3] = gg->noise & 1;
					}
				}
			}
		}
		gg->sample_clock += 44100;
		if (gg->sample_clock >= 3579545) {
			gg->sample_clock -= 3579545;
			int left = 0, right = 0;
			for (ch = 0; ch < 4; ch++) {
				// Sega tone periods 0 and 1 expose a DC level for volume-driven PCM.
				bool high = (ch < 3 && gg->tone[ch] <= 1) || gg->output[ch];
				int sample = amplitude[gg->volume[ch]] * (high? 1: -1);
				if (gg->stereo & (16 << ch)) {
					left += sample;
				}
				if (gg->stereo & (1 << ch)) {
					right += sample;
				}
			}
			r_write_le16 (gg->audio_pending + gg->audio_pending_size, left);
			r_write_le16 (gg->audio_pending + gg->audio_pending_size + 2, right);
			gg->audio_pending_size += 4;
			if (gg->audio_pending_size == sizeof (gg->audio_pending)) {
				gamegear_audio_flush (gg);
			}
		}
		if (++gg->dots == 228) {
			gg->dots = 0;
			if (gg->line < 192) {
				gamegear_scanline (gg, gg->line);
			}
			if (gg->line <= 192) {
				if (!gg->line_counter) {
					gg->line_counter = gg->vdp[10];
					gg->line_irq = true;
				} else {
					gg->line_counter--;
				}
			} else {
				gg->line_counter = gg->vdp[10];
			}
			if (++gg->line == 192) {
				gg->status |= 0x80;
				gg->frames++;
			}
			if (gg->line == 262) {
				gg->line = 0;
			}
		}
	}
}

static bool gamegear_condition(REsil *esil, int cc) {
	static const char *names[] = { "Z", "C", "P", "S" };
	bool value = gamegear_register_get (esil, names[cc / 2]);
	return (cc & 1)? value: !value;
}

static bool gamegear_step(RCore *core, RCoreGameGear *gg) {
	REsil *esil = &core->esil.esil;
	ut16 pc = gamegear_register_get (esil, "pc");
	bool irq = ((gg->status & 0x80) && (gg->vdp[1] & 0x20)) || (gg->line_irq && (gg->vdp[0] & 0x10));
	if (irq && gamegear_register_get (esil, "iff1") && !gamegear_register_get (esil, "ei")) {
		gamegear_register_set (esil, "halted", 0);
		gamegear_register_set (esil, "iff1", 0);
		gamegear_register_set (esil, "iff2", 0);
		ut16 sp = gamegear_register_get (esil, "sp") - 2;
		ut8 stack[2];
		r_write_le16 (stack, pc);
		gamegear_mem_write (esil, sp, stack, 2);
		gamegear_register_set (esil, "sp", sp);
		ut16 vector = 0x38;
		if (gamegear_register_get (esil, "im") == 2) {
			gamegear_mem_read (esil, (gamegear_register_get (esil, "i") << 8) | 0xff, stack, 2);
			vector = r_read_le16 (stack);
		}
		gamegear_register_set (esil, "mpc", vector);
		gamegear_tick (gg, gamegear_register_get (esil, "im") == 2? 19: 13);
		return true;
	}
	if (gamegear_register_get (esil, "halted")) {
		gamegear_tick (gg, 4);
		return true;
	}
	ut8 bytes[4];
	gamegear_mem_read (esil, pc, bytes, sizeof (bytes));
	GameGearInstruction decoded = {0};
	GameGearInstruction *instruction = gg->instructions? &gg->instructions[pc % GG_INSTRUCTION_CACHE_SIZE]: &decoded;
	if (!gamegear_instruction_decode (core, instruction, pc, bytes)) {
		R_LOG_ERROR ("Invalid Z80 opcode at 0x%04x", pc);
		return false;
	}
	int cycles = instruction->cycles;
	if (instruction->failcycles && ((bytes[0] & 0xc7) == 0xc0 || (bytes[0] & 0xc7) == 0xc4)) {
		if (!gamegear_condition (esil, (bytes[0] >> 3) & 7)) {
			cycles = instruction->failcycles;
		}
	} else if (bytes[0] >= 0x20 && bytes[0] <= 0x38 && !(bytes[0] & 7)) {
		if (!gamegear_condition (esil, (bytes[0] - 0x20) >> 3)) {
			cycles = instruction->failcycles;
		}
	} else if (bytes[0] == 0x10 && gamegear_register_get (esil, "b") == 1) {
		cycles = instruction->failcycles;
	}
	gamegear_register_set (esil, "mpc", (ut16)(pc + instruction->size));
	ut8 refresh = gamegear_register_get (esil, "r");
	int fetches = bytes[0] == 0xcb || bytes[0] == 0xed || bytes[0] == 0xdd || bytes[0] == 0xfd? 2: 1;
	gamegear_register_set (esil, "r", (refresh & 128) | ((refresh + fetches) & 127));
	esil->addr = pc;
	esil->trap = 0;
	const char *expression = instruction->expression;
	bool ok = !*expression || r_esil_parse (esil, expression);
	r_esil_stack_free (esil);
	if (bytes[0] == 0xed && bytes[1] >= 0xb0 && bytes[1] <= 0xbb && gamegear_register_get (esil, "pc") != pc) {
		cycles = 16;
	}
	free (decoded.expression);
	if (!ok || esil->trap) {
		R_LOG_ERROR ("Z80 ESIL failed at 0x%04x", pc);
		return false;
	}
	ut8 delay = gamegear_register_get (esil, "ei");
	if (delay) {
		gamegear_register_set (esil, "ei", --delay);
		if (!delay) {
			gamegear_register_set (esil, "iff1", 1);
			gamegear_register_set (esil, "iff2", 1);
		}
	}
	gamegear_register_set (esil, "mpc", (ut16)gamegear_register_get (esil, "pc"));
	gamegear_tick (gg, cycles);
	return true;
}

static bool gamegear_command(REsil *esil, const char *cmd, ut64 addr, ut64 value) {
	RCoreGameGear *gg = esil->cb.user;
	if (!strcmp (cmd, "gamegear.step")) {
		r_reg_setv (gg->core->anal->reg, "mpc", (ut16)addr);
		gamegear_step (gg->core, gg);
		return true;
	}
	if (!strcmp (cmd, "gamegear.tick")) {
		return false;
	}
	if (gg->previous_cmd) {
		return gg->previous_cmd (esil, cmd, addr, value);
	}
	r_core_cmdf (gg->core, "%s 0x%"PFMT64x" 0x%"PFMT64x, cmd, addr, value);
	return gg->core->num->value;
}

static void gamegear_fini(REsil *esil, void *user) {
	RCoreGameGear *gg = user;
	gamegear_audio_stop (gg);
	esil->cb = gg->callbacks;
	esil->cmd = gg->previous_cmd;
	if (gg->previous_step) {
		r_config_set (gg->core->config, "cmd.esil.step", gg->previous_step);
		r_config_set (gg->core->config, "cmd.esil.stepout", gg->previous_step_out);
	}
	free (gg->previous_step);
	free (gg->previous_step_out);
	if (gg->bank != UT32_MAX) {
		r_config_set (gg->core->config, "io.va", gg->previous_va? "true": "false");
		r_config_set (gg->core->config, "esil.skipself", gg->previous_skipself? "true": "false");
		r_io_bank_use (gg->io, gg->previous_bank);
		r_io_bank_del (gg->io, gg->bank);
	}
	int i;
	for (i = 0; i < gg->map_count; i++) {
		r_io_map_del (gg->io, gg->maps[i]);
	}
	if (gg->ram_fd >= 0) {
		r_io_fd_close (gg->io, gg->ram_fd);
	}
	if (gg->frame_fd >= 0) {
		r_io_fd_close (gg->io, gg->frame_fd);
	}
	if (gg->audio_fd >= 0) {
		r_io_fd_close (gg->io, gg->audio_fd);
	}
	if (gg->rom_fd >= 0) {
		r_io_fd_close (gg->io, gg->rom_fd);
	}
	r_flag_unset_name (gg->core->flags, "gg.framebuffer");
	r_flag_unset_name (gg->core->flags, "gg.audio");
	free (gg);
}

static void *gamegear_plugin_init(REsil *esil) {
	RCoreGameGear *gg = R_NEW0 (RCoreGameGear);
	gg->io = esil->anal->iob.io;
	gg->core = esil->anal->coreb.core;
	gg->previous_cmd = esil->cmd;
	gg->callbacks = esil->cb;
	gg->ram_fd = gg->frame_fd = gg->audio_fd = gg->rom_fd = -1;
	gg->bank = UT32_MAX;
	return gg;
}

static REsilPlugin gamegear_plugin = {
	.meta = { .name = "gamegear", .desc = "Game Gear ESIL peripherals", .license = "LGPL-3.0-only" },
	.init = gamegear_plugin_init,
	.fini = gamegear_fini,
};

static RIOMap *gamegear_map(RCoreGameGear *gg, int fd, int perm, ut64 delta, ut64 addr, ut64 size, const char *name) {
	RIOMap *map = r_io_map_add (gg->io, fd, perm, delta, addr, size);
	if (map) {
		r_io_map_set_name (map, name);
		gg->maps[gg->map_count++] = map->id;
	}
	return map;
}

static bool gamegear_init(RCore *core) {
	REsil *esil = &core->esil.esil;
	RCoreGameGear *previous = gamegear_get (esil);
	RBinFile *bf = r_bin_cur (core->bin);
	int fd = previous? previous->cart_fd: bf? bf->fd: r_io_fd_get_current (core->io);
	ut64 size = r_io_fd_size (core->io, fd);
	if (size < 0x4000 || size > 0x400000 || size % 0x4000) {
		R_LOG_ERROR ("Expected a raw Game Gear ROM, 16 KiB to 4 MiB in 16 KiB banks");
		return false;
	}
	r_esil_plugin_deactivate (esil, "gamegear");
	r_config_set (core->config, "asm.arch", "z80");
	r_config_set_i (core->config, "asm.bits", 16);
	r_libstore_add (esil->libstore, &gamegear_plugin);
	if (!r_esil_plugin_activate (esil, "gamegear")) {
		return false;
	}
	RCoreGameGear *gg = gamegear_get (esil);
	gg->cart_fd = fd;
	gg->previous_bank = core->io->bank;
	gg->previous_va = core->io->va;
	gg->previous_skipself = r_config_get_b (core->config, "esil.skipself");
	RIOBank *bank = r_io_bank_new ("gamegear");
	if (!bank || !r_io_bank_add (core->io, bank)) {
		r_io_bank_free (bank);
		goto fail;
	}
	gg->bank = bank->id;
	r_io_bank_use (core->io, gg->bank);
	r_config_set_b (core->config, "io.va", true);
	r_config_set_b (core->config, "esil.skipself", false);
	gg->rom_banks = size / 0x4000;
	char *uri = r_str_newf ("malloc://%"PFMT64u, size);
	RIODesc *rom = r_io_open_nomap (core->io, uri, R_PERM_RW, 0);
	free (uri);
	if (!rom) {
		goto fail;
	}
	gg->rom_fd = rom->fd;
	ut8 bytes[0x4000];
	ut32 i;
	for (i = 0; i < gg->rom_banks; i++) {
		if (r_io_fd_read_at (core->io, fd, i * sizeof (bytes), bytes, sizeof (bytes)) != sizeof (bytes)
				|| r_io_fd_write_at (core->io, rom->fd, i * sizeof (bytes), bytes, sizeof (bytes)) != sizeof (bytes)) {
			goto fail;
		}
	}
	RIODesc *ram = r_io_open_nomap (core->io, "malloc://0xa000", R_PERM_RWX, 0);
	if (!ram) {
		goto fail;
	}
	gg->ram_fd = ram->fd;
	RIODesc *frame = r_io_open_nomap (core->io, "malloc://69120", R_PERM_RW, 0);
	if (!frame) {
		goto fail;
	}
	gg->frame_fd = frame->fd;
	RIODesc *audio = r_io_open_nomap (core->io, "malloc://32768", R_PERM_RW, 0);
	if (!audio) {
		goto fail;
	}
	gg->audio_fd = audio->fd;
	if (!gamegear_map (gg, rom->fd, R_PERM_RX, 0, 0, 0x400, "gg.fixed")) {
		goto fail;
	}
	for (i = 0; i < 3; i++) {
		gg->mapper[i + 1] = i;
		ut32 offset = i == 0? 0x400: 0;
		RIOMap *map = gamegear_map (gg, rom->fd, R_PERM_RX, (i % gg->rom_banks) * 0x4000 + offset,
			i * 0x4000 + offset, 0x4000 - offset, "gg.rom");
		if (!map) {
			goto fail;
		}
		gg->slots[i] = map->id;
	}
	if (!gamegear_map (gg, ram->fd, R_PERM_RWX, 0, 0xc000, 0x2000, "gg.ram")
			|| !gamegear_map (gg, ram->fd, R_PERM_RWX, 0, 0xe000, 0x2000, "gg.echo")
			|| !gamegear_map (gg, frame->fd, R_PERM_RW, 0, GG_FRAMEBUFFER, GG_FRAME_SIZE, "gg.framebuffer")
			|| !gamegear_map (gg, audio->fd, R_PERM_RW, 0, GG_AUDIO_BUFFER, GG_AUDIO_SIZE, "gg.audio")) {
		goto fail;
	}
	gamegear_banks (gg);
	r_reg_arena_zero (core->anal->reg);
	r_reg_setv (core->anal->reg, "sp", 0xdff0);
	gg->stereo = 0xff;
	gg->noise = 0x8000;
	memset (gg->volume, 15, sizeof (gg->volume));
	gg->ports[1] = gg->ports[2] = gg->ports[3] = gg->ports[5] = 0xff;
	esil->cb.user = gg;
	esil->cb.hook_mem_read = gamegear_mem_read;
	esil->cb.hook_mem_write = gamegear_mem_write;
	gg->previous_step = strdup (r_config_get (core->config, "cmd.esil.step"));
	gg->previous_step_out = strdup (r_config_get (core->config, "cmd.esil.stepout"));
	r_config_set (core->config, "cmd.esil.step", "gamegear.step");
	r_config_set (core->config, "cmd.esil.stepout", "gamegear.tick");
	esil->cmd = gamegear_command;
	r_flag_set (core->flags, "gg.framebuffer", GG_FRAMEBUFFER, GG_FRAME_SIZE);
	r_flag_set (core->flags, "gg.audio", GG_AUDIO_BUFFER, GG_AUDIO_SIZE);
	return true;
fail:
	r_esil_plugin_deactivate (esil, "gamegear");
	return false;
}

static int gamegear_image_mode(RCoreGameGear *gg) {
	int color = r_config_get_i (gg->core->config, "scr.color");
	return color >= 3? 'r': color == 2? '2': color == 1? 'A': 'a';
}

static char *gamegear_screen(RCoreGameGear *gg) {
	ut8 *pixels = malloc (GG_FRAME_SIZE);
	if (!pixels) {
		return NULL;
	}
	if (r_io_fd_read_at (gg->io, gg->frame_fd, 0, pixels, GG_FRAME_SIZE) != GG_FRAME_SIZE) {
		free (pixels);
		R_LOG_ERROR ("Cannot read Game Gear framebuffer");
		return NULL;
	}
	char *screen = r_cons_image (pixels, GG_FRAME_SIZE, 160, gamegear_image_mode (gg), 3);
	free (pixels);
	return screen;
}

static char *gamegear_maps(RCoreGameGear *gg) {
	RStrBuf output;
	r_strbuf_initf (&output, "bank=%u\n", gg->bank);
	int i;
	for (i = 0; i < gg->map_count; i++) {
		RIOMap *map = r_io_map_get (gg->io, gg->maps[i]);
		if (map) {
			r_strbuf_appendf (&output, "0x%08"PFMT64x"-0x%08"PFMT64x" %s fd=%d offset=0x%08"PFMT64x" %s\n",
				r_io_map_begin (map), r_io_map_end (map) - 1, r_str_perm (map->perm, false), map->fd, map->delta, map->name);
		}
	}
	return r_strbuf_drain_nofree (&output);
}

#include "input.inc.c"

static char *gamegear_scaled(RCoreGameGear *gg, const ut8 *pixels, int cols, int rows) {
	int width = R_MIN (160, cols), height = R_MIN (144, rows * 2);
	if (width * 144 < height * 160) {
		height = width * 144 / 160;
	} else {
		width = height * 160 / 144;
	}
	width = R_MAX (1, width);
	height = R_MAX (2, height & ~1);
	ut8 *scaled = malloc (width * height * 3);
	if (!scaled) {
		return NULL;
	}
	int x, y, ch;
	for (y = 0; y < height; y++) {
		for (x = 0; x < width; x++) {
			int x0 = x * 160 / width, x1 = (x + 1) * 160 / width;
			int y0 = y * 144 / height, y1 = (y + 1) * 144 / height;
			for (ch = 0; ch < 3; ch++) {
				int sum = 0, sx, sy;
				for (sy = y0; sy < y1; sy++) {
					for (sx = x0; sx < x1; sx++) {
						sum += pixels[(sy * 160 + sx) * 3 + ch];
					}
				}
				scaled[(y * width + x) * 3 + ch] = sum / ((x1 - x0) * (y1 - y0));
			}
		}
	}
	char *result = r_cons_image (scaled, width * height * 3, width, gamegear_image_mode (gg), 3);
	free (scaled);
	return result;
}

static bool gamegear_visual_draw(RCoreGameGear *gg, ut8 *pixels, const GameGearInput *input) {
	RCons *cons = gg->core->cons;
	int rows;
	int cols = r_cons_get_size (cons, &rows);
	if (cols < 1 || rows < 3) {
		return true;
	}
	char *screen;
	if (cols >= 160 && rows >= 74) {
		screen = gamegear_screen (gg);
	} else {
		if (r_io_fd_read_at (gg->io, gg->frame_fd, 0, pixels, GG_FRAME_SIZE) != GG_FRAME_SIZE) {
			return false;
		}
		screen = gamegear_scaled (gg, pixels, cols, rows - 2);
	}
	if (!screen) {
		return false;
	}
	r_cons_gotoxy (cons, 1, 1);
	r_cons_println (cons, "r2gg | hjkl arrows | a/s A/B | F Start | q quit");
	r_cons_print (cons, screen);
	r_cons_printf (cons, "frames=%"PFMT64u" cycles=%"PFMT64u" input=%s", gg->frames, gg->cycles, input->event_types? "press/release": "timed");
	if (!input->event_types) {
		r_cons_printf (cons, " (%"PFMT64u" ms)", input->hold_us / 1000);
	}
	r_cons_newline (cons);
	r_cons_visual_flush (cons);
	free (screen);
	return true;
}

static void gamegear_visual(RCoreGameGear *gg, ut32 hold_ms) {
	RCore *core = gg->core;
	RCons *cons = core->cons;
	if (!r_cons_is_interactive (cons)) {
		R_LOG_ERROR ("Game Gear play mode requires scr.interactive=true");
		return;
	}
	ut8 *pixels = malloc (GG_FRAME_SIZE * 2);
	if (!pixels) {
		return;
	}
	gamegear_audio_flush (gg);
	gg->audio_consumed = gg->audio_produced;
	bool audio = gamegear_audio_start (gg);
	gg->instructions = calloc (GG_INSTRUCTION_CACHE_SIZE, sizeof (GameGearInstruction));
	if (!gg->instructions) {
		gamegear_audio_stop (gg);
		free (pixels);
		return;
	}
	GameGearRegisters registers = {0};
	gamegear_registers_init (&registers, core);
	bool previous_vmode = core->vmode;
	bool mouse = cons->mouse;
	ut64 backsteps = r_config_get_i (core->config, "esil.maxbacksteps");
	r_config_set_i (core->config, "esil.maxbacksteps", 0);
	core->vmode = true;
	gamegear_keys (gg, 0);
	r_io_bank_use (gg->io, gg->bank);
	r_cons_enable_mouse (cons, false);
	bool cup = !previous_vmode && r_cons_set_cup (true);
	r_cons_set_raw (cons, true);
	r_cons_show_cursor (cons, false);
	r_cons_print (cons, "\x1b[>11u\x1b[?u");
	r_cons_flush (cons);
	r_cons_clear (cons);
	r_cons_break_push (cons, NULL, NULL);
	GameGearInput input = { .hold_us = (ut64)hold_ms * 1000 };
	ut64 start = r_time_now_mono ();
	ut64 start_cycles = gg->cycles;
	ut64 next_render = 0;
	ut64 sleep_us = r_config_get_i (core->config, "gg.usleep");
	bool audio_ready = false;
	bool failed = false;
	while (!r_cons_is_breaked (cons) && gamegear_visual_input (gg, &input)) {
		if (audio) {
			gamegear_audio_flush (gg);
			if (!audio_ready && gg->audio_produced - gg->audio_consumed >= GG_AUDIO_PRIME_BYTES) {
				audio_ready = true;
				while (gg->audio_produced - gg->audio_consumed >= 2048 && gamegear_audio_submit (gg, false)) {
				}
			} else if (audio_ready) {
				gamegear_audio_submit (gg, false);
			}
		}
		ut64 now = r_time_now_mono ();
		if (now >= next_render) {
			if (!gamegear_visual_draw (gg, pixels, &input)) {
				break;
			}
			next_render = now + 33333;
		}
		now = r_time_now_mono ();
		ut64 elapsed = now - start;
		ut64 frame_end = ((elapsed * 3579545 / 1000000) / 59736 + 1) * 59736;
		ut64 target = frame_end + (audio? (ut64)GG_AUDIO_LEAD_US * 3579545 / 1000000: 0);
		if (gg->cycles - start_cycles >= target) {
			ut64 deadline = (frame_end * 1000000 + 3579545 - 1) / 3579545;
			ut64 wait = R_MIN (sleep_us, deadline - elapsed);
			if (wait) {
				r_sys_usleep (wait);
			}
			continue;
		}
		int i;
		bool stepped = true;
		for (i = 0; i < 256 && gg->cycles - start_cycles < target; i++) {
			if (!gamegear_step (core, gg)) {
				stepped = false;
				break;
			}
		}
		if (!stepped) {
			failed = true;
			break;
		}
	}
	r_cons_break_pop (cons);
	gamegear_registers_fini (&registers, core);
	gamegear_instructions_free (gg->instructions);
	gg->instructions = NULL;
	gamegear_audio_stop (gg);
	gamegear_keys (gg, 0);
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
	free (pixels);
	if (failed) {
		R_LOG_ERROR ("Game Gear stopped at 0x%04"PFMT64x" (ESIL trap %d, code %u)", r_reg_getv (core->anal->reg, "pc"), core->esil.esil.trap, core->esil.esil.trap_code);
	}
}

static char *gamegear_cmd(RCore *core, const char *cmd) {
	const char *input = r_str_trim_head_ro (cmd);
	if (*input == '?') {
		return strdup (
			"| r2gg          initialize Game Gear peripherals (Sega mapper)\n"
			"| r2gg-         release peripherals and restore the previous IO bank\n"
			"| r2gg keys N   held buttons: right=1 left=2 up=4 down=8 A=16 B=32 start=128\n"
			"| r2gg screen   render the 160x144 framebuffer using scr.color\n"
			"| r2gg audio    play pending stereo PCM through r2au (audio- stops playback)\n"
			"| r2gg play [hold-ms] play with hjkl, a/s, F, q; legacy key hold defaults to 500 ms\n"
			"| e gg.usleep=16000 maximum frame-deadline sleep in microseconds (0 disables sleeping)\n"
			"| r2gg maps     show runtime memory maps and active cartridge offsets\n"
			"| r2gg status   show emulated cycles and frames\n"
			"Use aes/aesu/aesue to execute; pri @0x10000!69120 prints the RGB framebuffer (hex.cols=160).");
	}
	REsil *esil = &core->esil.esil;
	if (!*input) {
		gamegear_init (core);
		return strdup ("");
	}
	RCoreGameGear *gg = gamegear_get (esil);
	if (!gg && (!strcmp (input, "play") || r_str_startswith (input, "play "))) {
		char *output = gamegear_cmd (core, "");
		free (output);
		gg = gamegear_get (esil);
	}
	if (!gg) {
		R_LOG_ERROR ("Initialize the Game Gear with r2gg first");
		return strdup ("");
	}
	gamegear_audio_flush (gg);
	if (!strcmp (input, "-")) {
		r_esil_plugin_deactivate (esil, "gamegear");
		r_flag_unset_name (core->flags, "gg.framebuffer");
		r_flag_unset_name (core->flags, "gg.audio");
	} else if (r_str_startswith (input, "keys ")) {
		gamegear_keys (gg, r_num_math (core->num, input + 5));
	} else if (!strcmp (input, "status")) {
		return r_str_newf ("cycles=%"PFMT64u" frames=%"PFMT64u" bank=%u audio=%"PFMT64u" offset=%"PFMT64u, gg->cycles, gg->frames, gg->bank, gg->audio_produced, gg->audio_produced % GG_AUDIO_SIZE);
	} else if (!strcmp (input, "screen")) {
		return gamegear_screen (gg);
	} else if (!strcmp (input, "maps")) {
		return gamegear_maps (gg);
	} else if (!strcmp (input, "audio")) {
		if (gamegear_audio_start (gg)) {
			while (gg->audio_consumed < gg->audio_produced && gamegear_audio_submit (gg, true)) {
			}
		}
	} else if (!strcmp (input, "audio-")) {
		gamegear_audio_stop (gg);
	} else if (!strcmp (input, "play") || r_str_startswith (input, "play ")) {
		ut64 hold_ms = input[4]? r_num_math (core->num, input + 5): 500;
		if (hold_ms < 1 || hold_ms > 5000) {
			R_LOG_ERROR ("Legacy key hold must be between 1 and 5000 ms");
		} else {
			gamegear_visual (gg, hold_ms);
		}
	} else {
		R_LOG_ERROR ("Unknown Game Gear peripheral command (r2gg?)");
	}
	return strdup ("");
}

static RCmdResult gamegear_call(RCmdContext *ctx) {
	RCore *core = ctx->user;
	char *output = gamegear_cmd (core, ctx->subcmd.a);
	if (R_STR_ISNOTEMPTY (output)) {
		r_cons_print (ctx->cons, output);
		if (output[strlen (output) - 1] != '\n') {
			r_cons_newline (ctx->cons);
		}
	}
	free (output);
	return (RCmdResult) { 0 };
}

static bool gamegear_sleep_config(void *user, void *data) {
	RConfigNode *node = data;
	if (node->i_value > 1000000) {
		R_LOG_ERROR ("gg.usleep must be between 0 and 1000000 microseconds");
		return false;
	}
	return true;
}

static bool gamegear_core_init(RCorePluginSession *session) {
	RConfig *config = session->core->config;
	bool locked = config->lock;
	r_config_lock (config, false);
	RConfigNode *node = r_config_set_i_cb (config, "gg.usleep", 16000, gamegear_sleep_config);
	r_config_desc (config, "gg.usleep", "Maximum sleep in microseconds while waiting for the next emulated frame (0 busy-waits)");
	r_config_lock (config, locked);
	return node != NULL;
}

static bool gamegear_core_fini(RCorePluginSession *session) {
	RCore *core = session->core;
	r_config_rm (core->config, "gg.usleep");
	if (core->esil.esil.libstore) {
		r_esil_plugin_del (&core->esil.esil, "gamegear");
	}
	r_flag_unset_name (core->flags, "gg.framebuffer");
	r_flag_unset_name (core->flags, "gg.audio");
	return true;
}

RCorePlugin r_core_plugin_gg = {
	.meta = {
		.name = "r2gg",
		.desc = "Game Gear ESIL emulator and framebuffer",
		.license = "LGPL-3.0-only",
	},
	.command = "r2gg",
	.call_ctx = gamegear_call,
	.init = gamegear_core_init,
	.fini = gamegear_core_fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_gg,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
