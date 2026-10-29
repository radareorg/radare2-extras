/* radare2 - LGPL - Copyright 2026 - pancake */
#define R2_PLUGIN_INCORE
#include "../core_gg.c"

#define CHECK(x) do { if (!(x)) { fprintf (stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); return false; } } while (0)

static bool test_peripherals(void) {
	RCore *core = r_core_new ();
	CHECK (r_core_file_open (core, "malloc://0x10000", R_PERM_RWX, 0));
	CHECK (r_core_bin_load (core, "malloc://0x10000", 0));
	ut8 byte = 0x5a;
	r_io_fd_write_at (core->io, r_bin_cur (core->bin)->fd, 0x8000, &byte, 1);
	CHECK (gamegear_init (core));
	REsil *esil = &core->esil.esil;
	RCoreGameGear *gg = gamegear_get (esil);
	CHECK (gg && core->io->bank != gg->previous_bank);
	byte = 2;
	gamegear_mem_write (esil, 0xfffe, &byte, 1);
	gamegear_mem_read (esil, 0x4000, &byte, 1);
	CHECK (byte == 0x5a);
	byte = 3;
	gamegear_mem_write (esil, 0xc123, &byte, 1);
	gamegear_mem_read (esil, 0xe123, &byte, 1);
	CHECK (byte == 3);
	byte = 8;
	gamegear_mem_write (esil, 0xfffc, &byte, 1);
	byte = 0xa5;
	gamegear_mem_write (esil, 0x8000, &byte, 1);
	byte = 12;
	gamegear_mem_write (esil, 0xfffc, &byte, 1);
	gamegear_mem_read (esil, 0x8000, &byte, 1);
	CHECK (!byte);
	byte = 8;
	gamegear_mem_write (esil, 0xfffc, &byte, 1);
	gamegear_mem_read (esil, 0x8000, &byte, 1);
	CHECK (byte == 0xa5);
	gamegear_keys (gg, 1 | 4 | 16 | 128);
	CHECK (gamegear_port_read (gg, 0xdc) == 0xe6);
	CHECK (gamegear_port_read (gg, 0) == 0x40);
	gamegear_keys (gg, 0);
	CHECK (gamegear_port_read (gg, 0xdc) == 0xff);
	// CRAM writes commit a 12-bit color on the second byte.
	gamegear_port_write (gg, 0xbf, 2);
	gamegear_port_write (gg, 0xbf, 0xc0);
	gamegear_port_write (gg, 0xbe, 0x3f);
	CHECK (!gg->cram[2]);
	gamegear_port_write (gg, 0xbe, 0x0a);
	CHECK (gg->cram[2] == 0x3f && gg->cram[3] == 0x0a);
	gg->vdp[1] = 0x60;
	gg->vdp[2] = 14;
	gg->vdp[5] = 0x7e;
	gg->vram[0x3f00] = 208;
	memset (gg->vram, 0xff, 32);
	int i;
	for (i = 0; i < 32; i += 4) {
		gg->vram[i + 1] = gg->vram[i + 2] = gg->vram[i + 3] = 0;
	}
	gamegear_scanline (gg, 24);
	ut8 rgb[3];
	r_io_fd_read_at (gg->io, gg->frame_fd, 0, rgb, 3);
	CHECK (rgb[0] == 255 && rgb[1] == 51 && rgb[2] == 170);
	gamegear_tick (gg, 192 * 228);
	CHECK (gg->frames == 1 && (gamegear_port_read (gg, 0xbf) & 0x80));
	CHECK (!(gg->status & 0x80));
	CHECK (gg->audio_produced > 0);
	gamegear_port_write (gg, 0xbf, 0x34);
	gamegear_port_write (gg, 0xbf, 0x40);
	gamegear_port_write (gg, 0xbe, 0x5a);
	gamegear_port_write (gg, 0xbe, 0xa5);
	gamegear_port_write (gg, 0xbf, 0x34);
	gamegear_port_write (gg, 0xbf, 0);
	CHECK (gamegear_port_read (gg, 0xbe) == 0x5a);
	CHECK (gamegear_port_read (gg, 0xbe) == 0xa5);
	gamegear_audio_flush (gg);
	ut64 offset = gg->audio_produced % GG_AUDIO_SIZE;
	gamegear_sound_write (gg, 0x81);
	gamegear_sound_write (gg, 0);
	gamegear_sound_write (gg, 0x90);
	gamegear_port_write (gg, 6, 0x10);
	gamegear_tick (gg, 512);
	gamegear_audio_flush (gg);
	ut8 pcm[4];
	r_io_fd_read_at (gg->io, gg->audio_fd, offset, pcm, sizeof (pcm));
	CHECK (r_read_le16 (pcm) != 0 && r_read_le16 (pcm + 2) == 0);
	ut32 previous = gg->previous_bank;
	r_esil_plugin_deactivate (esil, "gamegear");
	CHECK (core->io->bank == previous);
	CHECK (!r_flag_get (core->flags, "gg.framebuffer"));
	CHECK (!strcmp (r_config_get (core->config, "cmd.esil.step"), ""));
	r_core_free (core);
	return true;
}

static bool test_z80_bcd_arithmetic(void) {
	RCore *core = r_core_new ();
	CHECK (r_core_file_open (core, "malloc://0x8000", R_PERM_RWX, 0));
	CHECK (r_core_bin_load (core, "malloc://0x8000", 0));
	CHECK (gamegear_init (core));
	REsil *esil = &core->esil.esil;
	ut8 opcode[] = { 0x27 };
	RAnalOp op;
	r_anal_op_init (&op);
	r_anal_op_set_bytes (&op, 0, opcode, sizeof (opcode));
	CHECK (r_arch_session_decode (core->anal->arch->session, &op, R_ARCH_OP_MASK_ESIL));
	int left, right, sub, carry;
	for (left = 0; left < 100; left++) {
		for (right = 0; right < 100; right++) {
			for (sub = 0; sub < 2; sub++) {
				for (carry = 0; carry < 2; carry++) {
					int a = (left / 10) * 16 + left % 10;
					int b = (right / 10) * 16 + right % 10;
					int binary = sub? a - b - carry: a + b + carry;
					bool half = sub? (a & 15) < (b & 15) + carry: (a & 15) + (b & 15) + carry > 15;
					int decimal = sub? left - right - carry: left + right + carry;
					int wrapped = (decimal + 100) % 100;
					int expected = (wrapped / 10) * 16 + wrapped % 10;
					r_reg_setv (core->anal->reg, "a", binary & 255);
					r_reg_setv (core->anal->reg, "f", (sub? 2: 0) | (half? 16: 0) | ((binary < 0 || binary > 255)? 1: 0));
					CHECK (r_esil_parse (esil, r_strbuf_get (&op.esil)));
					CHECK (r_reg_getv (core->anal->reg, "a") == expected);
					CHECK (r_reg_getv (core->anal->reg, "C") == (decimal < 0 || decimal >= 100));
				}
			}
		}
	}
	r_anal_op_fini (&op);
	r_core_free (core);
	return true;
}

static bool test_psg_sample_mode(void) {
	RCore *core = r_core_new ();
	CHECK (r_core_file_open (core, "malloc://0x8000", R_PERM_RWX, 0));
	CHECK (r_core_bin_load (core, "malloc://0x8000", 0));
	CHECK (gamegear_init (core));
	RCoreGameGear *gg = gamegear_get (&core->esil.esil);
	gamegear_port_write (gg, 6, 0x10);
	int period, i;
	for (period = 0; period <= 1; period++) {
		gamegear_sound_write (gg, 0x80 | period);
		gamegear_sound_write (gg, 0);
		gamegear_sound_write (gg, 0x96);
		gamegear_audio_flush (gg);
		ut32 offset = gg->audio_produced;
		gamegear_tick (gg, 16000);
		gamegear_audio_flush (gg);
		ut8 samples[1024];
		int length = gg->audio_produced - offset;
		CHECK (length > 0 && length <= sizeof (samples));
		r_io_fd_read_at (gg->io, gg->audio_fd, offset, samples, length);
		for (i = 0; i < length; i += 4) {
			CHECK (r_read_le16 (samples + i) == 1029);
			CHECK (!r_read_le16 (samples + i + 2));
		}
	}
	gamegear_sound_write (gg, 0x95);
	ut32 offset = gg->audio_produced;
	gamegear_tick (gg, 100);
	gamegear_audio_flush (gg);
	ut8 sample[4];
	r_io_fd_read_at (gg->io, gg->audio_fd, offset, sample, sizeof (sample));
	CHECK (r_read_le16 (sample) == 1295);
	gamegear_sound_write (gg, 0x9f);
	offset = gg->audio_produced;
	gamegear_tick (gg, 100);
	gamegear_audio_flush (gg);
	r_io_fd_read_at (gg->io, gg->audio_fd, offset, sample, sizeof (sample));
	CHECK (!r_read_le16 (sample));
	r_core_free (core);
	return true;
}

static bool test_cpu_and_interrupts(void) {
	RCore *core = r_core_new ();
	CHECK (r_core_file_open (core, "malloc://0x8000", R_PERM_RWX, 0));
	CHECK (r_core_bin_load (core, "malloc://0x8000", 0));
	CHECK (gamegear_init (core));
	RCoreGameGear *gg = gamegear_get (&core->esil.esil);
	// LD, ADC, indexed LD and CB, OUT/IN, EI delay and HALT.
	ut8 program[] = { 0x3e, 0x7f, 0xc6, 1, 0xdd, 0x21, 0, 0xc1, 0xdd, 0x36, 0xff, 0x81,
		0xdd, 0xcb, 0xff, 0x06, 0x3e, 0x90, 0xd3, 0x7f, 0xdb, 0xdc, 0xfb, 0, 0x76 };
	r_io_write_at (core->io, 0xc000, program, sizeof (program));
	r_reg_setv (core->anal->reg, "mpc", 0xc000);
	CHECK (r_core_esil_single_step (core));
	CHECK (r_core_esil_single_step (core));
	CHECK (r_reg_getv (core->anal->reg, "a") == 0x80);
	CHECK (r_reg_getv (core->anal->reg, "f") == 0x94);
	CHECK (gamegear_step (core, gg));
	CHECK (gamegear_step (core, gg));
	CHECK (gamegear_step (core, gg));
	ut8 value;
	gamegear_mem_read (&core->esil.esil, 0xc0ff, &value, 1);
	CHECK (value == 3 && r_reg_getv (core->anal->reg, "C") == 1);
	int i;
	for (i = 0; i < 4; i++) {
		CHECK (gamegear_step (core, gg));
	}
	CHECK (gg->volume[0] == 0 && r_reg_getv (core->anal->reg, "iff1"));
	CHECK (r_reg_getv (core->anal->reg, "ei") == 1);
	gg->status = 0x80;
	gg->vdp[1] = 0x20;
	ut16 following = r_reg_getv (core->anal->reg, "pc");
	CHECK (gamegear_step (core, gg));
	CHECK (r_reg_getv (core->anal->reg, "pc") == following + 1);
	gg->status = 0;
	CHECK (r_reg_getv (core->anal->reg, "iff1"));
	CHECK (gamegear_step (core, gg));
	CHECK (r_reg_getv (core->anal->reg, "halted"));
	ut16 pc = r_reg_getv (core->anal->reg, "pc");
	CHECK (gamegear_step (core, gg));
	CHECK (r_reg_getv (core->anal->reg, "pc") == pc);
	gg->vdp[1] = 0x20;
	gg->status = 0x80;
	CHECK (gamegear_step (core, gg));
	CHECK (r_reg_getv (core->anal->reg, "pc") == 0x38);
	CHECK (!r_reg_getv (core->anal->reg, "halted"));
	ut8 stack[2];
	gamegear_mem_read (&core->esil.esil, r_reg_getv (core->anal->reg, "sp"), stack, 2);
	CHECK (r_read_le16 (stack) == pc);
	r_core_free (core);
	return true;
}

static bool test_register_cache(void) {
	RCore *core = r_core_new ();
	CHECK (r_core_file_open (core, "malloc://0x8000", R_PERM_RWX, 0));
	CHECK (r_core_bin_load (core, "malloc://0x8000", 0));
	CHECK (gamegear_init (core));
	REsil *esil = &core->esil.esil;
	REsilRegInterface previous = esil->reg_if;
	GameGearRegisters registers = {0};
	gamegear_registers_init (&registers, core);
	RListIter *iter;
	RRegItem *item;
	r_list_foreach (r_reg_get_list (core->anal->reg, R_REG_TYPE_ALL), iter, item) {
		ut64 value = 0xa55a123456789abcULL;
		CHECK (gamegear_register_write (&registers, item->name, value));
		CHECK (gamegear_register_get (esil, item->name) == r_reg_getv (core->anal->reg, item->name));
		CHECK (gamegear_register_size (&registers, item->name) == item->size);
	}
	gamegear_register_set (esil, "PC", 0x1234);
	CHECK (r_reg_getv (core->anal->reg, "mpc") == 0x1234);
	gamegear_register_set (esil, "SP", 0xc100);
	CHECK (r_reg_getv (core->anal->reg, "sp") == 0xc100);
	CHECK (!gamegear_register_item (&registers, "unknown"));
	ut8 byte = 0x7f, bytes[4];
	gamegear_mem_write (esil, 0xdfff, &byte, 1);
	gamegear_mem_read (esil, 0xffff, bytes, sizeof (bytes));
	CHECK (bytes[0] == 0x7f && !bytes[1] && !bytes[2] && !bytes[3]);
	gamegear_registers_fini (&registers, core);
	CHECK (esil->reg_if.reg == previous.reg && esil->reg_if.reg_read == previous.reg_read);
	r_core_free (core);
	return true;
}

typedef struct {
	ut32 initialized;
	ut32 stopped;
	ut32 bytes;
	ut32 nonzero;
} GameGearAudioBackend;

static RCmdResult gamegear_test_audio_call(RCmdContext *context) {
	RCorePluginSession *session = context->handler_user;
	GameGearAudioBackend *backend = session->data;
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

static bool test_r2au_streaming(void) {
	RCore *core = r_core_new ();
	CHECK (r_core_file_open (core, "malloc://0x8000", R_PERM_RWX, 0));
	CHECK (r_core_bin_load (core, "malloc://0x8000", 0));
	CHECK (r_core_plugin_add (core->rcmd, &r_core_plugin_gg));
	r_core_call (core, "r2gg");
	RCoreGameGear *gg = gamegear_get (&core->esil.esil);
	CHECK (gg);
	GameGearAudioBackend backend = {0};
	RCorePlugin audio_plugin = {
		.meta = { .name = "audio" },
		.command = "auq",
		.call_ctx = gamegear_test_audio_call,
	};
	CHECK (r_core_plugin_add (core->rcmd, &audio_plugin));
	RCorePluginSession *session = r_list_last (core->rcmd->libstore->plugins);
	session->data = &backend;
	gamegear_sound_write (gg, 0x81);
	gamegear_sound_write (gg, 0x10);
	gamegear_sound_write (gg, 0x90);
	gamegear_tick (gg, 357954);
	r_core_call (core, "r2gg audio");
	CHECK (backend.initialized == 1);
	CHECK (backend.bytes == gg->audio_produced && backend.nonzero > 0);
	CHECK (!strcmp (r_config_get (core->config, "asm.arch"), "z80"));
	ut32 queued = backend.bytes;
	r_core_call (core, "r2gg audio");
	CHECK (backend.bytes == queued && backend.initialized == 1);
	gamegear_tick (gg, 1000000);
	r_core_call (core, "r2gg audio");
	CHECK (backend.bytes == queued + GG_AUDIO_SIZE);
	r_core_call (core, "r2gg audio-");
	CHECK (backend.stopped == 1);
	r_core_call (core, "r2gg audio");
	CHECK (backend.initialized == 2);
	r_core_call (core, "r2gg-");
	CHECK (backend.stopped == 2);
	CHECK (!r_flag_get (core->flags, "gg.audio"));
	CHECK (r_core_plugin_remove (core->rcmd, &audio_plugin));
	r_core_free (core);
	return true;
}

static bool test_sleep_config(void) {
	RCore *core = r_core_new ();
	CHECK (r_core_plugin_add (core->rcmd, &r_core_plugin_gg));
	CHECK (r_config_get_i (core->config, "gg.usleep") == 16000);
	CHECK (r_config_set_i (core->config, "gg.usleep", 0));
	CHECK (r_config_set_i (core->config, "gg.usleep", 1000000));
	CHECK (r_config_get_i (core->config, "gg.usleep") == 1000000);
	CHECK (r_core_plugin_remove (core->rcmd, &r_core_plugin_gg));
	CHECK (!r_config_node_get (core->config, "gg.usleep"));
	r_core_free (core);
	return true;
}

static bool test_esil_opcode_stacks(void) {
	RCore *core = r_core_new ();
	CHECK (r_core_file_open (core, "malloc://0x8000", R_PERM_RWX, 0));
	CHECK (r_core_bin_load (core, "malloc://0x8000", 0));
	CHECK (gamegear_init (core));
	REsil *esil = &core->esil.esil;
	int group, code;
	for (group = 0; group < 7; group++) {
		for (code = 0; code < 256; code++) {
			ut8 bytes[4] = { code, 0, 0, 0 };
			if (group) {
				bytes[0] = group == 1? 0xcb: group == 2? 0xed: group & 1? 0xdd: 0xfd;
				bytes[1] = group >= 5? 0xcb: code;
				if (group >= 5) {
					bytes[3] = code;
				}
			}
			RAnalOp op;
			r_anal_op_init (&op);
			r_anal_op_set_bytes (&op, 0xc000, bytes, sizeof (bytes));
			if (!r_arch_session_decode (core->anal->arch->session, &op, R_ARCH_OP_MASK_ESIL)) {
				r_anal_op_fini (&op);
				continue;
			}
			r_reg_arena_zero (core->anal->reg);
			r_reg_setv (core->anal->reg, "sp", 0xc100);
			r_reg_setv (core->anal->reg, "hl", 0xc200);
			r_reg_setv (core->anal->reg, "ix", 0xc300);
			r_reg_setv (core->anal->reg, "iy", 0xc400);
			esil->trap = 0;
			const char *expression = r_strbuf_get (&op.esil);
			bool ok = !*expression || r_esil_parse (esil, expression);
			if (!ok || esil->stackptr || esil->trap) {
				fprintf (stderr, "Opcode group=%d code=%02x stack=%d trap=%d: %s\n", group, code, esil->stackptr, esil->trap, expression);
				r_anal_op_fini (&op);
				r_core_free (core);
				return false;
			}
			r_anal_op_fini (&op);
		}
	}
	r_core_free (core);
	return true;
}

int main(void) {
	if (!test_peripherals () || !test_psg_sample_mode () || !test_z80_bcd_arithmetic () || !test_cpu_and_interrupts () || !test_esil_opcode_stacks () || !test_r2au_streaming () || !test_register_cache () || !test_sleep_config ()) {
		return 1;
	}
	puts ("Game Gear peripheral, ESIL, interrupt and r2au streaming tests passed");
	return 0;
}
