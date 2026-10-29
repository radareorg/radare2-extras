/* radare2 - LGPL - Copyright 2026 - pancake */
#define R2_PLUGIN_INCORE
#include "../core_gg.c"

static FILE *audio;
static ut64 captured;

static bool capture_audio(RCoreGameGear *gg) {
	gamegear_audio_flush (gg);
	ut8 samples[4096];
	while (captured < gg->audio_produced) {
		ut32 offset = captured % GG_AUDIO_SIZE;
		ut32 length = R_MIN (sizeof (samples), R_MIN (gg->audio_produced - captured, GG_AUDIO_SIZE - offset));
		if (r_io_fd_read_at (gg->io, gg->audio_fd, offset, samples, length) != length
				|| fwrite (samples, 1, length, audio) != length) {
			return false;
		}
		captured += length;
	}
	return true;
}

static bool run_frames(RCoreGameGear *gg, int count) {
	ut64 target = gg->frames + count;
	ut64 limit = (ut64)count * 20000 + 100000;
	ut64 last_frame = gg->frames;
	while (gg->frames < target && limit--) {
		if (!gamegear_step (gg->core, gg)) {
			return false;
		}
		if (audio && last_frame != gg->frames) {
			if (!capture_audio (gg)) {
				return false;
			}
			last_frame = gg->frames;
		}
	}
	return gg->frames == target;
}

static void wave_header(ut32 bytes) {
	ut8 header[44] = {0};
	memcpy (header, "RIFF", 4);
	r_write_le32 (header + 4, bytes + 36);
	memcpy (header + 8, "WAVEfmt ", 8);
	r_write_le32 (header + 16, 16);
	r_write_le16 (header + 20, 1);
	r_write_le16 (header + 22, 2);
	r_write_le32 (header + 24, 44100);
	r_write_le32 (header + 28, 44100 * 4);
	r_write_le16 (header + 32, 4);
	r_write_le16 (header + 34, 16);
	memcpy (header + 36, "data", 4);
	r_write_le32 (header + 40, bytes);
	rewind (audio);
	fwrite (header, 1, sizeof (header), audio);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf (stderr, "Usage: %s sonic.gg [intro.wav]\n", argv[0]);
		return 1;
	}
	RCore *core = r_core_new ();
	if (!r_core_file_open (core, argv[1], R_PERM_R, 0) || !r_core_bin_load (core, argv[1], 0) || !gamegear_init (core)) {
		r_core_free (core);
		return 1;
	}
	RCoreGameGear *gg = gamegear_get (&core->esil.esil);
	gg->instructions = calloc (GG_INSTRUCTION_CACHE_SIZE, sizeof (GameGearInstruction));
	if (!gg->instructions) {
		r_core_free (core);
		return 1;
	}
	if (argc > 2) {
		audio = r_sandbox_fopen (argv[2], "wb");
		if (!audio) {
			gamegear_instructions_free (gg->instructions);
			gg->instructions = NULL;
			r_core_free (core);
			return 1;
		}
		wave_header (0);
	}
	GameGearRegisters registers = {0};
	gamegear_registers_init (&registers, core);
	bool ok = run_frames (gg, 500);
	if (audio) {
		ok = ok && capture_audio (gg);
		wave_header (captured);
		fclose (audio);
		audio = NULL;
	}
	gamegear_keys (gg, 128);
	ok = ok && run_frames (gg, 3);
	gamegear_keys (gg, 0);
	ok = ok && run_frames (gg, 1500);
	ut8 lives, state, clock[3];
	gamegear_mem_read (&core->esil.esil, 0xd240, &lives, 1);
	gamegear_mem_read (&core->esil.esil, 0xd205, &state, 1);
	gamegear_mem_read (&core->esil.esil, 0xd2cf, clock, 3);
	printf ("Sonic frame=%"PFMT64u" lives=%u death=%u pc=%04"PFMT64x"\n", gg->frames, lives, state & 1, gamegear_register_get (&core->esil.esil, "pc"));
	ok = ok && lives == 3 && !(state & 1) && clock[0] < 0x10 && clock[1] < 0x60 && clock[2] < 60;
	gamegear_registers_fini (&registers, core);
	gamegear_instructions_free (gg->instructions);
	gg->instructions = NULL;
	r_core_free (core);
	return ok? 0: 1;
}
