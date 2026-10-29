/* radare2 - LGPL - Copyright 2026 - pancake */
#define R2_PLUGIN_INCORE
#include "../core_gg.c"

static bool run_frames(RCoreGameGear *gg, int frames) {
	ut64 target = gg->frames + frames;
	ut64 count = 0;
	ut64 limit = (ut64)frames * 20000 + 100000;
	while (gg->frames < target && count++ < limit) {
		if (!gamegear_step (gg->core, gg)) {
			return false;
		}
		ut16 pc = gamegear_register_get (&gg->core->esil.esil, "pc");
		if (gg->cycles > 1000000 && (pc == 0 || pc == 0x7e)) {
			fprintf (stderr, "Columns rebooted at frame %"PFMT64u"\n", gg->frames);
			return false;
		}
	}
	return gg->frames == target;
}

static ut32 snapshot(RCoreGameGear *gg, const char *directory, const char *name) {
	ut8 pixels[GG_FRAME_SIZE];
	r_io_fd_read_at (gg->io, gg->frame_fd, 0, pixels, sizeof (pixels));
	ut32 hash = 2166136261U;
	int i;
	for (i = 0; i < sizeof (pixels); i++) {
		hash = (hash ^ pixels[i]) * 16777619U;
	}
	if (directory) {
		char *path = r_str_newf ("%s/columns-%s.rgb", directory, name);
		r_file_dump (path, pixels, sizeof (pixels), false);
		free (path);
	}
	printf ("%s: frame=%"PFMT64u" pc=%04"PFMT64x" rgb=%08x\n", name, gg->frames, r_reg_getv (gg->core->anal->reg, "pc"), hash);
	return hash;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf (stderr, "Usage: %s columns.gg [snapshot-directory]\n", argv[0]);
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
	GameGearRegisters registers = {0};
	gamegear_registers_init (&registers, core);
	ut64 start = r_time_now_mono ();
	bool ok = run_frames (gg, 500);
	const char *directory = argc > 2? argv[2]: NULL;
	ut32 title = snapshot (gg, directory, "title");
	char *attract_frames = r_sys_getenv ("R2GG_ATTRACT_FRAMES");
	if (attract_frames) {
		ok = ok && run_frames (gg, atoi (attract_frames));
		snapshot (gg, directory, "attract");
	} else {
		gamegear_keys (gg, 128);
		ok = ok && run_frames (gg, 3);
		gamegear_keys (gg, 0);
		ok = ok && run_frames (gg, 100);
		ut32 menu = snapshot (gg, directory, "menu");
		gamegear_keys (gg, 128);
		ok = ok && run_frames (gg, 3);
		gamegear_keys (gg, 0);
		ok = ok && run_frames (gg, 150);
		ut32 settings = snapshot (gg, directory, "settings");
		gamegear_keys (gg, 128);
		ok = ok && run_frames (gg, 3);
		gamegear_keys (gg, 0);
		char *game_frames = r_sys_getenv ("R2GG_GAME_FRAMES");
		ok = ok && run_frames (gg, game_frames? atoi (game_frames): 180);
		free (game_frames);
		ut32 game = snapshot (gg, directory, "game");
		ok = ok && title != menu && menu != settings && settings != game;
	}
	free (attract_frames);
	ut64 elapsed = r_time_now_mono () - start;
	printf ("elapsed=%.3f speed=%.2fx\n", elapsed / 1000000.0, gg->cycles * 1000000.0 / (3579545.0 * elapsed));
	gamegear_registers_fini (&registers, core);
	gamegear_instructions_free (gg->instructions);
	gg->instructions = NULL;
	r_core_free (core);
	return ok? 0: 1;
}
