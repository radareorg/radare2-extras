/* radare2 - LGPL - Copyright 2026 - pancake */

#include <r_core.h>
#include "apu.inc.c"
#include "registers.inc.c"
#include "instructions.inc.c"

#define GB_FRAMEBUFFER 0x10000
#define GB_FRAME_SIZE (160 * 144 * 3)

typedef struct {
	RIO *io;
	RCore *core;
	bool (*previous_cmd)(REsil *esil, const char *cmd, ut64 addr, ut64 value);
	char *previous_step;
	char *previous_step_out;
	ut8 cycles_table[512];
	ut8 failcycles_table[256];
	ut8 step_cycles;
	bool previous_va;
	bool previous_skipself;
	bool did_step;
	REsilCallbacks callbacks;
	ut32 bank;
	ut32 previous_bank;
	ut32 maps[7];
	int map_count;
	int ram_fd;
	int frame_fd;
	int audio_fd;
	GameBoyAPU apu;
	ut8 audio_pending[1024];
	ut32 audio_pending_size;
	ut64 audio_produced;
	ut64 audio_consumed;
	bool audio_playing;
	int cart_fd;
	int rom_fd;
	GameBoyInstruction *instructions;
	ut32 rom0;
	ut32 rom1;
	ut32 eram;
	ut32 rom_banks;
	ut32 ram_size;
	ut8 cartridge;
	ut8 rom_low;
	ut8 bank_high;
	ut8 banking_mode;
	bool ram_enabled;
	bool halted;
	bool halt_bug;
	bool stat_irq;
	ut8 ei_delay;
	ut8 keys;
	ut16 divider;
	ut32 dots;
	ut64 cycles;
	ut64 frames;
} RCoreGameBoy;

static RCoreGameBoy *gameboy_get(REsil *esil) {
	RListIter *iter;
	REsilActivePlugin *active;
	r_list_foreach (esil->active_plugins, iter, active) {
		if (!strcmp (active->plugin->meta.name, "gameboy")) {
			return active->user;
		}
	}
	return NULL;
}

static ut8 gameboy_read(RCoreGameBoy *gb, ut16 addr) {
	ut8 value = 0xff;
	r_io_bank_read_at (gb->io, gb->bank, addr, &value, 1);
	return value;
}

static void gameboy_write(RCoreGameBoy *gb, ut16 addr, ut8 value) {
	r_io_bank_write_at (gb->io, gb->bank, addr, &value, 1);
}

static void gameboy_request(RCoreGameBoy *gb, ut8 mask) {
	gameboy_write (gb, 0xff0f, gameboy_read (gb, 0xff0f) | mask);
}

static ut8 gameboy_joypad(RCoreGameBoy *gb) {
	ut8 select = gameboy_read (gb, 0xff00) & 0x30;
	ut8 buttons = 0xf;
	if (!(select & 0x10)) {
		buttons &= ~(gb->keys & 0xf);
	}
	if (!(select & 0x20)) {
		buttons &= ~(gb->keys >> 4);
	}
	return 0xc0 | select | buttons;
}

static void gameboy_keys(RCoreGameBoy *gb, ut8 keys) {
	if (keys != gb->keys) {
		ut8 old = gameboy_joypad (gb);
		gb->keys = keys;
		if (old & ~gameboy_joypad (gb) & 0xf) {
			gameboy_request (gb, 0x10);
		}
	}
}

static void gameboy_banks(RCoreGameBoy *gb) {
	RIOMap *rom0 = r_io_map_get (gb->io, gb->rom0);
	RIOMap *rom1 = r_io_map_get (gb->io, gb->rom1);
	RIOMap *eram = r_io_map_get (gb->io, gb->eram);
	ut32 upper = gb->bank_high << 5;
	if (rom0 && rom1) {
		rom0->delta = ((gb->banking_mode? upper: 0) % gb->rom_banks) * 0x4000;
		rom1->delta = ((upper | gb->rom_low) % gb->rom_banks) * 0x4000;
	}
	if (eram) {
		ut32 ram_bank = gb->banking_mode? gb->bank_high: 0;
		eram->delta = 0x10000 + (gb->ram_size? (ram_bank * 0x2000) % gb->ram_size: 0);
	}
}

static bool gameboy_mem_read(REsil *esil, ut64 addr, ut8 *buf, int len) {
	RCoreGameBoy *gb = esil->cb.user;
	int i;
	for (i = 0; i < len; i++) {
		ut16 at = addr + i;
		if (gb->ram_size == 0x800 && at >= 0xa000 && at < 0xc000) {
			at = 0xa000 | (at & 0x7ff);
		}
		if (at >= 0xff10 && at <= 0xff3f) {
			buf[i] = gameboy_apu_read (&gb->apu, at);
		} else if (at == 0xff00) {
			buf[i] = gameboy_joypad (gb);
		} else if ((at >= 0xa000 && at < 0xc000 && (!gb->ram_size || !gb->ram_enabled)) || (at >= 0xfea0 && at < 0xff00)) {
			buf[i] = 0xff;
		} else {
			buf[i] = gameboy_read (gb, at);
		}
	}
	return true;
}

static bool gameboy_timer_signal(RCoreGameBoy *gb) {
	static const ut8 bits[] = { 9, 3, 5, 7 };
	ut8 tac = gameboy_read (gb, 0xff07);
	return (tac & 4) && (gb->divider & (1 << bits[tac & 3]));
}

static void gameboy_timer_increment(RCoreGameBoy *gb) {
	ut8 tima = gameboy_read (gb, 0xff05) + 1;
	if (!tima) {
		tima = gameboy_read (gb, 0xff06);
		gameboy_request (gb, 4);
	}
	gameboy_write (gb, 0xff05, tima);
}

static bool gameboy_mem_write(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	RCoreGameBoy *gb = esil->cb.user;
	int i;
	for (i = 0; i < len; i++) {
		ut16 at = addr + i;
		if (gb->ram_size == 0x800 && at >= 0xa000 && at < 0xc000) {
			at = 0xa000 | (at & 0x7ff);
		}
		ut8 value = buf[i];
		if (at < 0x8000) {
			if (gb->cartridge >= 1 && gb->cartridge <= 3) {
				if (at < 0x2000) {
					gb->ram_enabled = (value & 0xf) == 0xa;
				} else if (at < 0x4000) {
					gb->rom_low = value & 0x1f;
					if (!gb->rom_low) {
						gb->rom_low = 1;
					}
				} else if (at < 0x6000) {
					gb->bank_high = value & 3;
				} else {
					gb->banking_mode = value & 1;
				}
				gameboy_banks (gb);
			}
			continue;
		}
		if ((at >= 0xa000 && at < 0xc000 && (!gb->ram_size || !gb->ram_enabled)) || (at >= 0xfea0 && at < 0xff00) || at == 0xff44) {
			continue;
		}
		if (at >= 0xff10 && at <= 0xff3f) {
			gameboy_apu_write (&gb->apu, at, value);
			int port;
			for (port = 0xff10; port <= 0xff3f; port++) {
				gameboy_write (gb, port, gameboy_apu_read (&gb->apu, port));
			}
			continue;
		}
		bool timer_signal = gameboy_timer_signal (gb);
		switch (at) {
		case 0xff00:
			value = 0xc0 | (value & 0x30) | 0xf;
			break;
		case 0xff04:
			if (gb->divider & 0x1000) {
				gameboy_apu_frame (&gb->apu);
			}
			gb->divider = 0;
			value = 0;
			break;
		case 0xff07:
			value |= 0xf8;
			break;
		case 0xff0f:
			value |= 0xe0;
			break;
		case 0xff41:
			value = 0x80 | (value & 0x78) | (gameboy_read (gb, at) & 7);
			break;
		case 0xff46: {
			ut8 oam[0xa0];
			r_io_bank_read_at (gb->io, gb->bank, value << 8, oam, sizeof (oam));
			r_io_bank_write_at (gb->io, gb->bank, 0xfe00, oam, sizeof (oam));
			break;
		}
		}
		gameboy_write (gb, at, value);
		if ((at == 0xff04 || at == 0xff07) && timer_signal && !gameboy_timer_signal (gb)) {
			gameboy_timer_increment (gb);
		}
	}
	return true;
}

static ut8 gameboy_tile_pixel(const ut8 *vram, int tile, int x, int y) {
	int offset = tile + y * 2;
	int shift = 7 - x;
	return ((vram[offset] >> shift) & 1) | (((vram[offset + 1] >> shift) & 1) << 1);
}

static void gameboy_scanline(RCoreGameBoy *gb, int y) {
	ut8 vram[0x2000], oam[0xa0], ports[0x0c];
	ut8 line[160 * 3], background[160];
	r_io_bank_read_at (gb->io, gb->bank, 0x8000, vram, sizeof (vram));
	r_io_bank_read_at (gb->io, gb->bank, 0xfe00, oam, sizeof (oam));
	r_io_bank_read_at (gb->io, gb->bank, 0xff40, ports, sizeof (ports));
	ut8 lcdc = ports[0];
	int x;
	for (x = 0; x < 160; x++) {
		ut8 color = 0;
		if (lcdc & 1) {
			bool window = (lcdc & 0x20) && y >= ports[0xa] && x >= (int)ports[0xb] - 7;
			int px = window? x - ((int)ports[0xb] - 7): (x + ports[3]) & 255;
			int py = window? y - ports[0xa]: (y + ports[2]) & 255;
			int map = (lcdc & (window? 0x40: 8))? 0x1c00: 0x1800;
			ut8 index = vram[map + (py / 8) * 32 + px / 8];
			int tile = (lcdc & 0x10)? index * 16: 0x1000 + (st8)index * 16;
			color = gameboy_tile_pixel (vram, tile, px & 7, py & 7);
		}
		background[x] = color;
		ut8 shade = 255 - ((ports[7] >> (color * 2)) & 3) * 85;
		memset (line + x * 3, shade, 3);
	}
	if (lcdc & 2) {
		int selected[10], count = 0;
		int height = (lcdc & 4)? 16: 8;
		int i, j;
		for (i = 0; i < 40 && count < 10; i++) {
			int sy = (int)oam[i * 4] - 16;
			if (y >= sy && y < sy + height) {
				selected[count++] = i;
			}
		}
		for (i = 1; i < count; i++) {
			int sprite = selected[i];
			for (j = i; j > 0 && oam[selected[j - 1] * 4 + 1] > oam[sprite * 4 + 1]; j--) {
				selected[j] = selected[j - 1];
			}
			selected[j] = sprite;
		}
		for (x = 0; x < 160; x++) {
			for (i = 0; i < count; i++) {
				const ut8 *obj = oam + selected[i] * 4;
				int sx = (int)obj[1] - 8;
				if (x < sx || x >= sx + 8) {
					continue;
				}
				int py = y - ((int)obj[0] - 16);
				int px = x - sx;
				if (obj[3] & 0x40) {
					py = height - 1 - py;
				}
				if (obj[3] & 0x20) {
					px = 7 - px;
				}
				int tile = ((height == 16)? obj[2] & 0xfe: obj[2]) * 16;
				ut8 color = gameboy_tile_pixel (vram, tile, px, py);
				if (!color) {
					continue;
				}
				if (!(obj[3] & 0x80) || !background[x]) {
					ut8 palette = ports[(obj[3] & 0x10)? 9: 8];
					ut8 shade = 255 - ((palette >> (color * 2)) & 3) * 85;
					memset (line + x * 3, shade, 3);
				}
				break;
			}
		}
	}
	r_io_fd_write_at (gb->io, gb->frame_fd, y * sizeof (line), line, sizeof (line));
}

static void gameboy_audio_flush(RCoreGameBoy *gb) {
	if (!gb->audio_pending_size) {
		return;
	}
	ut32 offset = gb->audio_produced % GB_AUDIO_SIZE;
	ut32 first = R_MIN (gb->audio_pending_size, GB_AUDIO_SIZE - offset);
	r_io_fd_write_at (gb->io, gb->audio_fd, offset, gb->audio_pending, first);
	if (first < gb->audio_pending_size) {
		r_io_fd_write_at (gb->io, gb->audio_fd, 0, gb->audio_pending + first, gb->audio_pending_size - first);
	}
	gb->audio_produced += gb->audio_pending_size;
	gb->audio_pending_size = 0;
}

static void gameboy_audio_stop(RCoreGameBoy *gb) {
	if (gb->audio_playing) {
		r_core_call (gb->core, "auq-");
		gb->audio_playing = false;
	}
}

static bool gameboy_audio_start(RCoreGameBoy *gb) {
	if (gb->audio_playing) {
		return true;
	}
	RCore *core = gb->core;
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
	gb->audio_playing = core->num->value == 1;
	return gb->audio_playing;
}

static bool gameboy_audio_submit(RCoreGameBoy *gb, bool partial) {
	gameboy_audio_flush (gb);
	if (gb->audio_produced - gb->audio_consumed > GB_AUDIO_SIZE) {
		gb->audio_consumed = gb->audio_produced - GB_AUDIO_SIZE;
	}
	if (!partial && gb->audio_produced - gb->audio_consumed < 2048) {
		return true;
	}
	ut32 offset = gb->audio_consumed % GB_AUDIO_SIZE;
	ut32 length = R_MIN (gb->audio_produced - gb->audio_consumed, GB_AUDIO_SIZE - offset);
	length = R_MIN (length, 4096);
	if (!length) {
		return true;
	}
	char command[80];
	snprintf (command, sizeof (command), "auq 0x%x %u", GB_AUDIO_BUFFER + offset, length);
	r_core_call (gb->core, command);
	if (gb->core->num->value == length) {
		gb->audio_consumed += length;
		return true;
	}
	return false;
}

static void gameboy_tick(RCoreGameBoy *gb, int cycles) {
	static const ut8 timer_bits[] = { 9, 3, 5, 7 };
	ut8 ports[0x80];
	r_io_fd_read_at (gb->io, gb->ram_fd, 0xff00, ports, sizeof (ports));
	ut16 timer_mask = 1 << timer_bits[ports[7] & 3];
	int i;
	for (i = 0; i < cycles; i++) {
		bool timer_signal = (ports[7] & 4) && (gb->divider & timer_mask);
		ut16 previous_divider = gb->divider++;
		if ((previous_divider & 0x1000) && !(gb->divider & 0x1000)) {
			gameboy_apu_frame (&gb->apu);
		}
		if (gameboy_apu_tick (&gb->apu, gb->audio_pending + gb->audio_pending_size)) {
			gb->audio_pending_size += 4;
			if (gb->audio_pending_size == sizeof (gb->audio_pending)) {
				gameboy_audio_flush (gb);
			}
		}
		if (timer_signal && !(gb->divider & timer_mask)) {
			if (!++ports[5]) {
				ports[5] = ports[6];
				ports[0xf] |= 4;
			}
		}
		ports[4] = gb->divider >> 8;
		gb->cycles++;
		if (!(ports[0x40] & 0x80)) {
			gb->dots = 0;
			ports[0x44] = 0;
			ports[0x41] &= 0xf8;
			gb->stat_irq = false;
			continue;
		}
		gb->dots = (gb->dots + 1) % 70224;
		int y = gb->dots / 456;
		int dot = gb->dots % 456;
		ut8 mode = y >= 144? 1: dot < 80? 2: dot < 252? 3: 0;
		ports[0x44] = y;
		if (y < 144 && dot == 252) {
			r_io_fd_write_at (gb->io, gb->ram_fd, 0xff00, ports, sizeof (ports));
			gameboy_scanline (gb, y);
		}
		if (gb->dots == 144 * 456) {
			ports[0xf] |= 1;
			gb->frames++;
		}
		ut8 stat = (ports[0x41] & 0xf8) | mode;
		if (y == ports[0x45]) {
			stat |= 4;
		}
		ports[0x41] = stat;
		bool irq = ((stat & 0x40) && (stat & 4)) || (mode == 0 && (stat & 8)) || (mode == 1 && (stat & 0x10)) || (mode == 2 && (stat & 0x20));
		if (irq && !gb->stat_irq) {
			ports[0xf] |= 2;
		}
		gb->stat_irq = irq;
	}
	ports[0x26] = gameboy_apu_read (&gb->apu, 0xff26);
	r_io_fd_write_at (gb->io, gb->ram_fd, 0xff00, ports, sizeof (ports));
}

static void gameboy_fini(REsil *esil, void *user) {
	RCoreGameBoy *gb = user;
	gameboy_audio_stop (gb);
	esil->cb = gb->callbacks;
	esil->cmd = gb->previous_cmd;
	if (gb->previous_step) {
		r_config_set (gb->core->config, "cmd.esil.step", gb->previous_step);
		r_config_set (gb->core->config, "cmd.esil.stepout", gb->previous_step_out);
	}
	free (gb->previous_step);
	free (gb->previous_step_out);
	if (gb->bank != UT32_MAX) {
		r_config_set (gb->core->config, "io.va", gb->previous_va? "true": "false");
		r_config_set (gb->core->config, "esil.skipself", gb->previous_skipself? "true": "false");
		r_io_bank_use (gb->io, gb->previous_bank);
		r_io_bank_del (gb->io, gb->bank);
	}
	int i;
	for (i = 0; i < gb->map_count; i++) {
		r_io_map_del (gb->io, gb->maps[i]);
	}
	if (gb->ram_fd >= 0) {
		r_io_fd_close (gb->io, gb->ram_fd);
	}
	if (gb->frame_fd >= 0) {
		r_io_fd_close (gb->io, gb->frame_fd);
	}
	if (gb->audio_fd >= 0) {
		r_io_fd_close (gb->io, gb->audio_fd);
	}
	if (gb->rom_fd >= 0) {
		r_io_fd_close (gb->io, gb->rom_fd);
	}
	free (gb);
}

static void *gameboy_plugin_init(REsil *esil) {
	RCoreGameBoy *gb = R_NEW0 (RCoreGameBoy);
	gb->io = esil->anal->iob.io;
	gb->core = esil->anal->coreb.core;
	gb->previous_cmd = esil->cmd;
	gb->callbacks = esil->cb;
	gb->ram_fd = gb->frame_fd = gb->audio_fd = gb->rom_fd = -1;
	gb->bank = UT32_MAX;
	return gb;
}

static REsilPlugin gameboy_plugin = {
	.meta = { .name = "gameboy", .desc = "Game Boy ESIL peripherals", .license = "LGPL-3.0-only" },
	.init = gameboy_plugin_init,
	.fini = gameboy_fini,
};

static RIOMap *gameboy_map(RCoreGameBoy *gb, int fd, int perm, ut64 delta, ut64 addr, ut64 size, const char *name) {
	RIOMap *map = r_io_map_add (gb->io, fd, perm, delta, addr, size);
	if (map) {
		r_io_map_set_name (map, name);
		gb->maps[gb->map_count++] = map->id;
	}
	return map;
}

static bool gameboy_init(RCore *core) {
	REsil *esil = &core->esil.esil;
	RCoreGameBoy *previous = gameboy_get (esil);
	RBinFile *bf = r_bin_cur (core->bin);
	int fd = previous? previous->cart_fd: bf? bf->fd: r_io_fd_get_current (core->io);
	ut8 header[0x150];
	ut64 size = r_io_fd_size (core->io, fd);
	if (size < sizeof (header) || r_io_fd_read_at (core->io, fd, 0, header, sizeof (header)) != sizeof (header)) {
		R_LOG_ERROR ("Cannot read Game Boy cartridge header");
		return false;
	}
	ut8 cartridge = header[0x147];
	if (header[0x143] == 0xc0) {
		R_LOG_ERROR ("CGB-only cartridges are not supported by the DMG peripheral model");
		return false;
	}
	if (cartridge > 3 && cartridge != 8 && cartridge != 9) {
		R_LOG_ERROR ("Unsupported cartridge controller 0x%02x (ROM and MBC1 supported)", cartridge);
		return false;
	}
	if (size < 0x8000 || size % 0x4000 || size > 0x200000) {
		R_LOG_ERROR ("Invalid ROM size for ROM/MBC1 cartridge");
		return false;
	}
	r_config_set (core->config, "asm.arch", "gb");
	r_config_set (core->config, "asm.bits", "16");
	r_esil_plugin_deactivate (esil, "gameboy");
	r_libstore_add (esil->libstore, &gameboy_plugin);
	if (!r_esil_plugin_activate (esil, "gameboy")) {
		return false;
	}
	RCoreGameBoy *gb = gameboy_get (esil);
	gb->previous_bank = core->io->bank;
	gb->previous_va = core->io->va;
	gb->previous_skipself = r_config_get_b (core->config, "esil.skipself");
	RIOBank *bank = r_io_bank_new ("gameboy");
	if (!bank || !r_io_bank_add (core->io, bank)) {
		r_io_bank_free (bank);
		goto fail;
	}
	gb->bank = bank->id;
	r_config_set (core->config, "io.va", "true");
	r_config_set (core->config, "esil.skipself", "false");
	r_io_bank_use (core->io, gb->bank);
	gb->cart_fd = fd;
	gb->cartridge = cartridge;
	gb->rom_banks = size / 0x4000;
	gb->rom_low = 1;
	static const ut32 ram_sizes[] = { 0, 0x800, 0x2000, 0x8000 };
	gb->ram_size = header[0x149] < R_ARRAY_SIZE (ram_sizes)? ram_sizes[header[0x149]]: 0;
	gb->ram_enabled = cartridge == 8 || cartridge == 9;
	char rom_uri[64];
	snprintf (rom_uri, sizeof (rom_uri), "malloc://%"PFMT64u, size);
	RIODesc *rom = r_io_open_nomap (core->io, rom_uri, R_PERM_RW, 0);
	if (!rom) {
		goto fail;
	}
	gb->rom_fd = rom->fd;
	ut8 rom_bank[0x4000];
	ut32 rom_bank_index;
	for (rom_bank_index = 0; rom_bank_index < gb->rom_banks; rom_bank_index++) {
		ut32 offset = rom_bank_index * sizeof (rom_bank);
		if (r_io_fd_read_at (core->io, fd, offset, rom_bank, sizeof (rom_bank)) != sizeof (rom_bank)
				|| r_io_fd_write_at (core->io, rom->fd, offset, rom_bank, sizeof (rom_bank)) != sizeof (rom_bank)) {
			R_LOG_ERROR ("Cannot load Game Boy cartridge into memory");
			goto fail;
		}
	}
	RIODesc *ram = r_io_open_nomap (core->io, "malloc://0x18000", R_PERM_RWX, 0);
	if (!ram) {
		goto fail;
	}
	gb->ram_fd = ram->fd;
	RIODesc *frame = r_io_open_nomap (core->io, "malloc://69120", R_PERM_RW, 0);
	if (!frame) {
		goto fail;
	}
	gb->frame_fd = frame->fd;
	RIODesc *audio = r_io_open_nomap (core->io, "malloc://32768", R_PERM_RW, 0);
	if (!audio) {
		goto fail;
	}
	gb->audio_fd = audio->fd;
	RIOMap *map = gameboy_map (gb, rom->fd, R_PERM_RX, 0, 0, 0x4000, "gb.rom0");
	if (!map) {
		goto fail;
	}
	gb->rom0 = map->id;
	map = gameboy_map (gb, rom->fd, R_PERM_RX, 0x4000, 0x4000, 0x4000, "gb.rom1");
	if (!map) {
		goto fail;
	}
	gb->rom1 = map->id;
	if (!gameboy_map (gb, ram->fd, R_PERM_RWX, 0x8000, 0x8000, 0x8000, "gb.ram") || !gameboy_map (gb, ram->fd, R_PERM_RWX, 0xc000, 0xe000, 0x1e00, "gb.echo")) {
		goto fail;
	}
	map = gameboy_map (gb, ram->fd, R_PERM_RW, 0x10000, 0xa000, gb->ram_size == 0x800? 0x800: 0x2000, "gb.eram");
	if (!map) {
		goto fail;
	}
	gb->eram = map->id;
	if (!gameboy_map (gb, frame->fd, R_PERM_RW, 0, GB_FRAMEBUFFER, GB_FRAME_SIZE, "gb.framebuffer")) {
		goto fail;
	}
	if (!gameboy_map (gb, audio->fd, R_PERM_RW, 0, GB_AUDIO_BUFFER, GB_AUDIO_SIZE, "gb.audio")) {
		goto fail;
	}
	esil->cb.user = gb;
	esil->cb.hook_mem_read = gameboy_mem_read;
	esil->cb.hook_mem_write = gameboy_mem_write;
	r_reg_setv (core->anal->reg, "mpc", 0x100);
	r_reg_setv (core->anal->reg, "sp", 0xfffe);
	r_reg_setv (core->anal->reg, "af", 0x01b0);
	r_reg_setv (core->anal->reg, "bc", 0x0013);
	r_reg_setv (core->anal->reg, "de", 0x00d8);
	r_reg_setv (core->anal->reg, "hl", 0x014d);
	r_reg_setv (core->anal->reg, "ime", 0);
	gameboy_write (gb, 0xff00, 0xcf);
	gameboy_write (gb, 0xff0f, 0xe1);
	gameboy_write (gb, 0xff40, 0x91);
	gameboy_write (gb, 0xff41, 0x82);
	gameboy_write (gb, 0xff47, 0xfc);
	gameboy_write (gb, 0xff48, 0xff);
	gameboy_write (gb, 0xff49, 0xff);
	gameboy_apu_write (&gb->apu, 0xff26, 0x80);
	static const ut8 sound[] = { 0x80, 0xbf, 0xf3, 0xff, 0xbf, 0xff, 0x3f, 0, 0xff, 0xbf, 0x7f, 0xff, 0x9f, 0xff, 0xbf, 0xff, 0xff, 0, 0, 0xbf, 0x77, 0xf3 };
	int sound_index;
	for (sound_index = 0; sound_index < R_ARRAY_SIZE (sound); sound_index++) {
		// Trigger bits are read as ones but must not trigger boot tones here.
		ut8 value = sound[sound_index];
		if (sound_index < 0x14 && sound_index % 5 == 4) {
			value &= 0x7f;
		}
		gameboy_apu_write (&gb->apu, 0xff10 + sound_index, value);
	}
	for (sound_index = 0xff10; sound_index <= 0xff3f; sound_index++) {
		gameboy_write (gb, sound_index, gameboy_apu_read (&gb->apu, sound_index));
	}
	r_flag_set (core->flags, "gb.audio", GB_AUDIO_BUFFER, GB_AUDIO_SIZE);
	r_config_set (core->config, "hex.cols", "160");
	r_flag_set (core->flags, "gb.framebuffer", GB_FRAMEBUFFER, GB_FRAME_SIZE);
	return true;
fail:
	r_esil_plugin_deactivate (esil, "gameboy");
	return false;
}

static bool gameboy_step(RCore *core, RCoreGameBoy *gb) {
	REsil *esil = &core->esil.esil;
	ut8 pending = gameboy_read (gb, 0xff0f) & gameboy_read (gb, 0xffff) & 0x1f;
	if (pending) {
		gb->halted = false;
		if (gameboy_register_get (esil, "ime")) {
			int bit = 0;
			while (!(pending & (1 << bit))) {
				bit++;
			}
			ut16 sp = gameboy_register_get (esil, "sp") - 2;
			ut8 saved_pc[2];
			r_write_le16 (saved_pc, gameboy_register_get (esil, "pc"));
			r_esil_mem_write (esil, sp, saved_pc, 2);
			gameboy_register_set (esil, "sp", sp);
			gameboy_register_set (esil, "pc", 0x40 + bit * 8);
			gameboy_register_set (esil, "ime", 0);
			gameboy_write (gb, 0xff0f, gameboy_read (gb, 0xff0f) & ~(1 << bit));
			gameboy_tick (gb, 20);
			return true;
		}
	}
	if (gb->halted) {
		gameboy_tick (gb, 4);
		return true;
	}
	ut16 pc = gameboy_register_get (esil, "pc");
	ut8 bytes[3];
	int i;
	if (pc <= 0xfffd && !gb->halt_bug) {
		r_io_bank_read_at (gb->io, gb->bank, pc, bytes, sizeof (bytes));
	} else {
		for (i = 0; i < 3; i++) {
			bytes[i] = gameboy_read (gb, pc + i - (gb->halt_bug && i > 0? 1: 0));
		}
	}
	GameBoyInstruction decoded = {0};
	GameBoyInstruction *instruction = gb->instructions? &gb->instructions[pc % GB_INSTRUCTION_CACHE_SIZE]: &decoded;
	if (!gameboy_instruction_decode (core, instruction, pc, bytes)) {
		R_LOG_ERROR ("Invalid Game Boy opcode %02x at 0x%04x", bytes[0], pc);
		return false;
	}
	int cycles = instruction->cycles;
	if (instruction->failcycles) {
		bool condition = gameboy_register_get (esil, (bytes[0] & 0x10)? "C": "Z");
		if (!(bytes[0] & 8)) {
			condition = !condition;
		}
		if (!condition) {
			cycles = instruction->failcycles;
		}
	}
	gameboy_register_set (esil, "pc", (ut16)(pc + instruction->size - gb->halt_bug));
	gb->halt_bug = false;
	esil->addr = pc;
	esil->trap = 0;
	if (bytes[0] == 0x76 || bytes[0] == 0x10) {
		if (pending && !gameboy_register_get (esil, "ime")) {
			gb->halt_bug = true;
		} else {
			gb->halted = true;
		}
	} else if (bytes[0] == 0xfb) {
		if (!gb->ei_delay) {
			gb->ei_delay = 2;
		}
	} else {
		r_esil_parse (esil, instruction->expression);
		if (bytes[0] == 0xf3) {
			gb->ei_delay = 0;
		}
	}
	r_esil_stack_free (esil);
	free (decoded.expression);
	if (esil->trap) {
		R_LOG_ERROR ("Game Boy ESIL trap at 0x%04x", pc);
		return false;
	}
	if (gb->ei_delay && !--gb->ei_delay) {
		gameboy_register_set (esil, "ime", 1);
	}
	gameboy_tick (gb, cycles);
	return true;
}

static bool gameboy_before(RCoreGameBoy *gb, ut16 pc) {
	RReg *reg = gb->core->anal->reg;
	ut8 opcode = gameboy_read (gb, pc);
	ut8 pending = gameboy_read (gb, 0xff0f) & gameboy_read (gb, 0xffff) & 0x1f;
	gb->did_step = false;
	if (gb->halt_bug || gb->halted || (pending && r_reg_getv (reg, "ime"))) {
		r_reg_setv (reg, "pc", pc);
		gameboy_step (gb->core, gb);
		gb->did_step = true;
		return true;
	}
	if (pending) {
		gb->halted = false;
	}
	gb->step_cycles = gb->cycles_table[opcode == 0xcb? 256 + gameboy_read (gb, pc + 1): opcode];
	if (gb->failcycles_table[opcode]) {
		bool condition = r_reg_getv (reg, (opcode & 0x10)? "C": "Z");
		if (!(opcode & 8)) {
			condition = !condition;
		}
		if (!condition) {
			gb->step_cycles = gb->failcycles_table[opcode];
		}
	}
	if (opcode == 0xfb) {
		if (!gb->ei_delay) {
			gb->ei_delay = 2;
		}
		return true;
	}
	if (opcode == 0xf3) {
		gb->ei_delay = 0;
	} else if (opcode == 0x76 || opcode == 0x10) {
		if (pending && !r_reg_getv (reg, "ime")) {
			gb->halt_bug = true;
		} else {
			gb->halted = true;
		}
	}
	return false;
}

static bool gameboy_command(REsil *esil, const char *cmd, ut64 addr, ut64 value) {
	RCoreGameBoy *gb = esil->cb.user;
	if (!strcmp (cmd, "gameboy.step")) {
		return gameboy_before (gb, addr);
	}
	if (!strcmp (cmd, "gameboy.tick")) {
		r_reg_setv (gb->core->anal->reg, "mpc", (ut16)r_reg_getv (gb->core->anal->reg, "pc"));
		if (!gb->did_step) {
			if (gb->ei_delay && !--gb->ei_delay) {
				r_reg_setv (gb->core->anal->reg, "ime", 1);
			}
			gameboy_tick (gb, gb->step_cycles);
		}
		return false;
	}
	if (gb->previous_cmd) {
		return gb->previous_cmd (esil, cmd, addr, value);
	}
	RCore *core = gb->core;
	r_core_cmdf (core, "%s 0x%"PFMT64x" 0x%"PFMT64x, cmd, addr, value);
	return core->num->value;
}

static int gameboy_image_mode(RCoreGameBoy *gb) {
	int color = r_config_get_i (gb->core->config, "scr.color");
	return color >= 3? 'r': color == 2? '2': color == 1? 'A': 'a';
}

static char *gameboy_screen(RCoreGameBoy *gb) {
	ut8 *pixels = malloc (GB_FRAME_SIZE);
	if (!pixels) {
		return NULL;
	}
	if (r_io_fd_read_at (gb->io, gb->frame_fd, 0, pixels, GB_FRAME_SIZE) != GB_FRAME_SIZE) {
		free (pixels);
		R_LOG_ERROR ("Cannot read Game Boy framebuffer");
		return NULL;
	}
	char *screen = r_cons_image (pixels, GB_FRAME_SIZE, 160, gameboy_image_mode (gb), 3);
	free (pixels);
	return screen;
}

static char *gameboy_maps(RCoreGameBoy *gb) {
	RStrBuf output;
	r_strbuf_initf (&output, "bank=%u\n", gb->bank);
	int i;
	for (i = 0; i < gb->map_count; i++) {
		RIOMap *map = r_io_map_get (gb->io, gb->maps[i]);
		if (map) {
			r_strbuf_appendf (&output, "0x%08"PFMT64x"-0x%08"PFMT64x" %s fd=%d offset=0x%08"PFMT64x" %s\n",
				r_io_map_begin (map), r_io_map_end (map) - 1, r_str_perm (map->perm, false), map->fd, map->delta, map->name);
		}
	}
	return r_strbuf_drain_nofree (&output);
}

#include "input.inc.c"

static ut8 gameboy_filtered_pixel(const ut8 *pixels, int x, int y, int width, int height) {
	int x0 = x * 160 / width;
	int x1 = ((x + 1) * 160 + width - 1) / width;
	int y0 = y * 144 / height;
	int y1 = ((y + 1) * 144 + height - 1) / height;
	ut32 sum = 0, weight = 0;
	int sx, sy;
	for (sy = y0; sy < y1; sy++) {
		int wy = R_MIN ((sy + 1) * height, (y + 1) * 144) - R_MAX (sy * height, y * 144);
		for (sx = x0; sx < x1; sx++) {
			int wx = R_MIN ((sx + 1) * width, (x + 1) * 160) - R_MAX (sx * width, x * 160);
			const ut8 *pixel = pixels + (sy * 160 + sx) * 3;
			ut32 shade = (pixel[0] + pixel[1] + pixel[2]) / 3;
			sum += shade * wx * wy;
			weight += wx * wy;
		}
	}
	return (sum + weight / 2) / weight;
}

static char *gameboy_braille(RCoreGameBoy *gb, ut8 *pixels, int cols, int rows) {
	int width = R_MIN (cols, 80) * 2;
	int height = R_MIN (rows, 36) * 4;
	if (width * 144 < height * 160) {
		height = width * 144 / 160;
	} else {
		width = height * 160 / 144;
	}
	width = R_MAX (2, width & ~1);
	height = R_MAX (4, height & ~3);
	ut8 *scaled = pixels + GB_FRAME_SIZE;
	int x, y;
	for (y = 0; y < height; y++) {
		for (x = 0; x < width; x++) {
			scaled[y * width + x] = gameboy_filtered_pixel (pixels, x, y, width, height);
		}
	}
	static const int dots[8] = { _BR00, _BR01, _BR10, _BR11, _BR20, _BR21, _BR30, _BR31 };
	bool color = r_config_get_i (gb->core->config, "scr.color") > 0;
	RStrBuf output;
	r_strbuf_init (&output);
	for (y = 0; y < height; y += 4) {
		for (x = 0; x < width; x += 2) {
			ut8 samples[8];
			int low = 255, high = 0;
			int i;
			for (i = 0; i < 8; i++) {
				samples[i] = scaled[(y + i / 2) * width + x + i % 2];
				low = R_MIN (low, samples[i]);
				high = R_MAX (high, samples[i]);
			}
			int threshold = (low + high) / 2;
			int mask = 0, dark = 0, light = 0, count = 0;
			for (i = 0; i < 8; i++) {
				if (samples[i] < threshold) {
					mask |= dots[i];
					dark += samples[i];
					count++;
				} else {
					light += samples[i];
				}
			}
			if (color) {
				ut8 fg = count? dark / count: low;
				ut8 bg = light / (8 - count);
				RColor pair = { .a = ALPHA_FGBG, .r = fg, .g = fg, .b = fg, .r2 = bg, .g2 = bg, .b2 = bg, .id16 = -1 };
				char sequence[128];
				r_cons_rgb_str (gb->core->cons, sequence, sizeof (sequence), &pair);
				r_strbuf_append (&output, sequence);
			}
			RBraile cell = r_print_braile (mask);
			r_strbuf_append (&output, cell.str);
		}
		r_strbuf_append (&output, color? Color_RESET"\n": "\n");
	}
	return r_strbuf_drain_nofree (&output);
}

static bool gameboy_visual_draw(RCoreGameBoy *gb, ut8 *pixels, const GameBoyInput *input) {
	RCons *cons = gb->core->cons;
	int rows;
	int cols = r_cons_get_size (cons, &rows);
	if (cols < 1 || rows < 3) {
		return true;
	}
	char *screen;
	if (cols >= 160 && rows >= 74) {
		screen = gameboy_screen (gb);
	} else {
		if (r_io_fd_read_at (gb->io, gb->frame_fd, 0, pixels, GB_FRAME_SIZE) != GB_FRAME_SIZE) {
			return false;
		}
		screen = gameboy_braille (gb, pixels, cols, rows - 2);
	}
	if (!screen) {
		return false;
	}
	r_cons_gotoxy (cons, 1, 1);
	r_cons_println (cons, "r2gb | hjkl arrows | a/s A/B | D/F Select/Start | q quit");
	r_cons_print (cons, screen);
	r_cons_printf (cons, "frames=%"PFMT64u" cycles=%"PFMT64u" input=%s", gb->frames, gb->cycles, input->event_types? "press/release": "timed");
	if (!input->event_types) {
		r_cons_printf (cons, " (%"PFMT64u" ms)", input->hold_us / 1000);
	}
	r_cons_newline (cons);
	r_cons_visual_flush (cons);
	free (screen);
	return true;
}

static void gameboy_visual(RCoreGameBoy *gb, ut32 hold_ms) {
	RCore *core = gb->core;
	RCons *cons = core->cons;
	if (!r_cons_is_interactive (cons)) {
		R_LOG_ERROR ("Game Boy play mode requires scr.interactive=true");
		return;
	}
	ut8 *pixels = malloc (GB_FRAME_SIZE * 2);
	if (!pixels) {
		return;
	}
	gameboy_audio_flush (gb);
	gb->audio_consumed = gb->audio_produced;
	bool audio = gameboy_audio_start (gb);
	gb->instructions = calloc (GB_INSTRUCTION_CACHE_SIZE, sizeof (GameBoyInstruction));
	if (!gb->instructions) {
		gameboy_audio_stop (gb);
		free (pixels);
		return;
	}
	GameBoyRegisters registers = {0};
	gameboy_registers_init (&registers, core);
	bool previous_vmode = core->vmode;
	bool mouse = cons->mouse;
	ut64 backsteps = r_config_get_i (core->config, "esil.maxbacksteps");
	r_config_set_i (core->config, "esil.maxbacksteps", 0);
	core->vmode = true;
	gameboy_keys (gb, 0);
	r_io_bank_use (gb->io, gb->bank);
	r_cons_enable_mouse (cons, false);
	bool cup = !previous_vmode && r_cons_set_cup (true);
	r_cons_set_raw (cons, true);
	r_cons_show_cursor (cons, false);
	r_cons_print (cons, "\x1b[>11u\x1b[?u");
	r_cons_flush (cons);
	r_cons_clear (cons);
	r_cons_break_push (cons, NULL, NULL);
	GameBoyInput input = { .hold_us = (ut64)hold_ms * 1000 };
	ut64 start = r_time_now_mono ();
	ut64 start_cycles = gb->cycles;
	ut64 next_render = 0;
	ut64 sleep_us = r_config_get_i (core->config, "gb.usleep");
	bool audio_ready = false;
	bool failed = false;
	while (!r_cons_is_breaked (cons) && gameboy_visual_input (gb, &input)) {
		if (audio) {
			gameboy_audio_flush (gb);
			if (!audio_ready && gb->audio_produced - gb->audio_consumed >= 8192) {
				audio_ready = true;
				while (gb->audio_produced - gb->audio_consumed >= 2048 && gameboy_audio_submit (gb, false)) {
				}
			} else if (audio_ready) {
				gameboy_audio_submit (gb, false);
			}
		}
		ut64 now = r_time_now_mono ();
		if (now >= next_render) {
			if (!gameboy_visual_draw (gb, pixels, &input)) {
				break;
			}
			next_render = now + 33333;
		}
		now = r_time_now_mono ();
		ut64 elapsed = now - start;
		ut64 frame_end = ((elapsed * 4194304 / 1000000) / 70224 + 1) * 70224;
		ut64 target = frame_end + (audio? (ut64)50000 * 4194304 / 1000000: 0);
		if (gb->cycles - start_cycles >= target) {
			ut64 deadline = (frame_end * 1000000 + 4194304 - 1) / 4194304;
			ut64 wait = R_MIN (sleep_us, deadline - elapsed);
			if (wait) {
				r_sys_usleep (wait);
			}
			continue;
		}
		int i;
		bool stepped = true;
		for (i = 0; i < 256 && gb->cycles - start_cycles < target; i++) {
			if (!gameboy_step (core, gb)) {
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
	gameboy_registers_fini (&registers, core);
	gameboy_instructions_free (gb->instructions);
	gb->instructions = NULL;
	gameboy_audio_stop (gb);
	gameboy_keys (gb, 0);
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
		R_LOG_ERROR ("Game Boy stopped at 0x%04"PFMT64x" (ESIL trap %d, code %u)", r_reg_getv (core->anal->reg, "pc"), core->esil.esil.trap, core->esil.esil.trap_code);
	}
}

static char *gameboy_cmd(RCore *core, const char *cmd) {
	const char *input = r_str_trim_head_ro (cmd);
	if (*input == '?') {
		return strdup (
			"| r2gb          initialize Game Boy peripherals (DMG, ROM/MBC1)\n"
			"| r2gb-         release peripherals and restore the previous IO bank\n"
			"| r2gb keys N   held buttons: right=1 left=2 up=4 down=8 A=16 B=32 select=64 start=128\n"
			"| r2gb screen   render the 160x144 framebuffer using scr.color\n"
			"| r2gb audio    play pending stereo PCM through r2au (audio- stops playback)\n"
			"| r2gb play [hold-ms] play with hjkl, a/s, D/F, q; legacy key hold defaults to 500 ms\n"
			"| e gb.usleep=16000 maximum frame-deadline sleep in microseconds (0 disables sleeping)\n"
			"| r2gb maps     show runtime memory maps and active cartridge offsets\n"
			"| r2gb status   show emulated cycles and frames\n"
			"Use aes/aesu/aesue to execute; pri @0x10000!69120 prints the RGB framebuffer (hex.cols=160).");
	}
	REsil *esil = &core->esil.esil;
	if (!*input) {
		if (gameboy_init (core)) {
			RCoreGameBoy *gb = gameboy_get (esil);
			int i;
			for (i = 0; i < 512; i++) {
				ut8 bytes[3] = { i < 256? i: 0xcb, i < 256? 0: i - 256, 0 };
				RAnalOp op;
				r_anal_op_init (&op);
				r_anal_op_set_bytes (&op, 0, bytes, sizeof (bytes));
				r_arch_session_decode (core->anal->arch->session, &op, R_ARCH_OP_MASK_BASIC);
				gb->cycles_table[i] = op.cycles;
				if (i < 256) {
					gb->failcycles_table[i] = op.failcycles;
				}
				r_anal_op_fini (&op);
			}
			gb->previous_step = strdup (r_config_get (core->config, "cmd.esil.step"));
			gb->previous_step_out = strdup (r_config_get (core->config, "cmd.esil.stepout"));
			r_config_set (core->config, "cmd.esil.step", "gameboy.step");
			r_config_set (core->config, "cmd.esil.stepout", "gameboy.tick");
			esil->cmd = gameboy_command;
		}
		return strdup ("");
	}
	RCoreGameBoy *gb = gameboy_get (esil);
	if (!gb && (!strcmp (input, "play") || r_str_startswith (input, "play "))) {
		char *output = gameboy_cmd (core, "");
		free (output);
		gb = gameboy_get (esil);
	}
	if (!gb) {
		R_LOG_ERROR ("Initialize the Game Boy with r2gb first");
		return strdup ("");
	}
	gameboy_audio_flush (gb);
	if (!strcmp (input, "-")) {
		r_esil_plugin_deactivate (esil, "gameboy");
		r_flag_unset_name (core->flags, "gb.framebuffer");
		r_flag_unset_name (core->flags, "gb.audio");
	} else if (r_str_startswith (input, "keys ")) {
		gameboy_keys (gb, r_num_math (core->num, input + 5));
	} else if (!strcmp (input, "status")) {
		return r_str_newf ("cycles=%"PFMT64u" frames=%"PFMT64u" bank=%u audio=%"PFMT64u" offset=%"PFMT64u, gb->cycles, gb->frames, gb->bank, gb->audio_produced, gb->audio_produced % GB_AUDIO_SIZE);
	} else if (!strcmp (input, "screen")) {
		return gameboy_screen (gb);
	} else if (!strcmp (input, "maps")) {
		return gameboy_maps (gb);
	} else if (!strcmp (input, "audio")) {
		if (gameboy_audio_start (gb)) {
			while (gb->audio_consumed < gb->audio_produced && gameboy_audio_submit (gb, true)) {
			}
		}
	} else if (!strcmp (input, "audio-")) {
		gameboy_audio_stop (gb);
	} else if (!strcmp (input, "play") || r_str_startswith (input, "play ")) {
		ut64 hold_ms = input[4]? r_num_math (core->num, input + 5): 500;
		if (hold_ms < 1 || hold_ms > 5000) {
			R_LOG_ERROR ("Legacy key hold must be between 1 and 5000 ms");
		} else {
			gameboy_visual (gb, hold_ms);
		}
	} else {
		R_LOG_ERROR ("Unknown Game Boy peripheral command (r2gb?)");
	}
	return strdup ("");
}

static RCmdResult gameboy_call(RCmdContext *ctx) {
	RCore *core = ctx->user;
	char *output = gameboy_cmd (core, ctx->subcmd.a);
	if (R_STR_ISNOTEMPTY (output)) {
		r_cons_print (ctx->cons, output);
		if (output[strlen (output) - 1] != '\n') {
			r_cons_newline (ctx->cons);
		}
	}
	free (output);
	return (RCmdResult) { 0 };
}

static bool gameboy_sleep_config(void *user, void *data) {
	RConfigNode *node = data;
	if (node->i_value > 1000000) {
		R_LOG_ERROR ("gb.usleep must be between 0 and 1000000 microseconds");
		return false;
	}
	return true;
}

static bool gameboy_core_init(RCorePluginSession *session) {
	RConfig *config = session->core->config;
	bool locked = config->lock;
	r_config_lock (config, false);
	RConfigNode *node = r_config_set_i_cb (config, "gb.usleep", 16000, gameboy_sleep_config);
	r_config_desc (config, "gb.usleep", "Maximum sleep in microseconds while waiting for the next emulated frame (0 busy-waits)");
	r_config_lock (config, locked);
	return node != NULL;
}

static bool gameboy_core_fini(RCorePluginSession *session) {
	RCore *core = session->core;
	r_config_rm (core->config, "gb.usleep");
	if (core->esil.esil.libstore) {
		r_esil_plugin_del (&core->esil.esil, "gameboy");
	}
	r_flag_unset_name (core->flags, "gb.framebuffer");
	r_flag_unset_name (core->flags, "gb.audio");
	return true;
}

RCorePlugin r_core_plugin_gb = {
	.meta = {
		.name = "r2gb",
		.desc = "Game Boy ESIL emulator and framebuffer",
		.license = "LGPL-3.0-only",
	},
	.command = "r2gb",
	.call_ctx = gameboy_call,
	.init = gameboy_core_init,
	.fini = gameboy_core_fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_gb,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
