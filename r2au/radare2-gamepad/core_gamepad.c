/* radare - LGPL - Copyright 2018 - pancake */

#include <SDL.h>
#include <r_core.h>

#undef R_API
#define R_API static
#undef R_IPI
#define R_IPI static

#define JOY_LEFT 1
#define JOY_RIGHT 2
#define JOY_UP 4
#define JOY_DOWN 8
#define JOY_BUTTON 16

#define THRESHOLD 200

static bool sdl_init() {
	if (SDL_Init (SDL_INIT_VIDEO|SDL_INIT_JOYSTICK) < 0) {
		eprintf ("Cannot initialize joystick\n");
		return false;
	}
	if (SDL_NumJoysticks() < 1) {
		eprintf ("Cannot find any joystick\n");
		return false;
	}
	r_cons_break_push (NULL, NULL);
	return true;
}

static ut64 now = UT64_MAX;
static ut32 sdl_gamepad() {
	SDL_Event e;
	r_sys_usleep (50000);
	if (now == UT64_MAX) {
		r_sys_now ();
	}
	if (r_cons_is_breaked ()) {
		return UT32_MAX;
	}
	SDL_Joystick *gc = SDL_JoystickOpen (0);
	if (!gc) {
		return UT32_MAX;
	}
	int event = 0;
	while (SDL_PollEvent (&e) != 0) {
		if (e.type == SDL_QUIT) {
			//			break;
		}
		switch (e.type) {
		case SDL_JOYAXISMOTION:
			{
				int axis = e.jaxis.axis;
				int direction = e.jaxis.value > THRESHOLD;
				char *k[2][2] = {
					{ "LEFT", "RIGHT" },
					{ "UP", "DOWN" },
				};
				int q[2][2] = {
					{ JOY_LEFT, JOY_RIGHT },
					{ JOY_UP, JOY_DOWN }
				};
				if (e.jaxis.value < THRESHOLD && e.jaxis.value > -THRESHOLD) {
					// printf ("no move %s down by %d\n", k[axis][direction], e.jaxis.value);
				} else {
					ut64 nuw = r_sys_now ();
					if (nuw > now + 100000 ) {
						event |= q[axis][direction];
						now = nuw;
					}
					// printf ("%s down\n", k[axis][direction]);
				}
			}
#if 0
			printf ("t: %d w: %d a: %d v: %d\n", 
					e.jaxis.type,
					e.jaxis.which,
					e.jaxis.axis,
					e.jaxis.value);
#endif
			break;
		case SDL_JOYBUTTONDOWN:
			{
				ut64 nuw = r_sys_now ();
				if (nuw > now + 1000 ) {
					event |= JOY_BUTTON << e.jbutton.button;
					now = nuw;
				}
			}
			break;
		case SDL_JOYBUTTONUP:
			// printf ("%d up state = %d\n", e.jbutton.button, e.jbutton.state);
			break;
		}

	}
	SDL_JoystickClose (gc);
	return event;
}

static void sdl_fini () {
	r_cons_break_pop ();
	SDL_Quit ();
}

const char *cmd = "px 0x200";
const int bSELECT = 0x1000;
const int bSTART= 0x2000;
const int bACCEPT = 0x20;
const int bCANCEL = 0x40;
const int bPREV = 0x100;
const int bNEXT = 0x400;
bool jamMode = false;

static bool menu_render(RCore *core, const char *title, const char **args, int index) {
	int i;
	r_cons_printf (" [%s]\n", title);
	for (i=0;;i++) {
		if (!args[i]) {
			break;
		}
		const char *mark = (i == index)? ">": " ";
		r_cons_printf (" %s %2d  %s\n", mark, i, args[i]);
	}
	return true;
}

static int menu (RCore *core, const char *title, const char **args) {
	int index = 0;
	menu_render (core, title, args, index);
	r_cons_flush ();
	for (;;) {
		int k = sdl_gamepad ();
		if (k == -1) {
			break;
		}
		if (k) {
			r_cons_clear00 ();
			if (k & JOY_UP) {
				if (index > 0) {
					index--;
				}
			}
			if (k & JOY_DOWN) {
				if (!args[++index]) {
					index--;
				}
			}
			if (k & bACCEPT) {
				printf ("ACTION (%s)\n", args[index]);
				sleep(1);
				break;
			}
			if (k & bCANCEL) {
				printf ("CANCEL\n");
				sleep(1);
				break;
			}
			menu_render (core, title, args, index);
			r_cons_flush ();
		}
	}
	return index;
}

static void render (RCore *core, int k) {
	if (jamMode) {
		// TODO
	} else {
		if (k & JOY_UP) {
			if (cmd[1] == 'x') {
				r_core_cmd0 (core, "s-16");
			} else {
				r_core_cmd0 (core, "so-1");
			}
		} else if (k & JOY_DOWN) {
			if (cmd[1] == 'x') {
				r_core_cmd0 (core, "s+16");
			} else {
				r_core_cmd0 (core, "so");
			}
		}
		if (k & JOY_RIGHT) {
			r_core_cmd0 (core, "s+1");
		} else if (k & JOY_LEFT) {
			r_core_cmd0 (core, "s-1");
		}
	}
	if (k & bSTART) {
		const char *args[] = {
			"Analyze Function",
			"Disassemble",
			"Hexdump",
			"Audio Wave",
			"Audio Jam",
			"Quit",
			NULL
		};
		jamMode = false;
		switch (menu (core, "MENU", args)) {
		case 0:
			r_core_cmd0 (core, "af");
			break;
		case 1:
			cmd = "pd $r-2";
			break;
		case 2:
			cmd = "px $r*16";
			break;
		case 3:
			cmd = "aup";
			break;
		case 4:
			cmd = "aupi;aup";
			jamMode = true;
			break;
		case 5:
			cmd = NULL;
			break;
		}
	}
	if (k & JOY_BUTTON << 0) {
		r_core_cmd0 (core, "e scr.color=0");
	}
	if (k & JOY_BUTTON << 1) {
		r_core_cmd0 (core, "e scr.color=3");
	}
	if (k & JOY_BUTTON << 2) {
		cmd = "pd 30";
	}
	if (k & JOY_BUTTON << 3) {
		// cmd = "pxr 64";
		cmd = "px 0x200";
	}
	if (k & JOY_BUTTON << 4) {
		r_core_cmd0 (core, "e scr.color=3");
	}
	if (k & JOY_BUTTON << 5) {
		cmd = "pd 30";
	}
	r_cons_clear00 ();
	// r_cons_gotoxy (0, 0);
	r_cons_printf ("K = %x\n", k);
	if (cmd) {
		r_core_cmd0 (core, cmd);
	}
	r_cons_flush ();
}

static void visual_gamepad(RCore *core) {
	if (sdl_init ()) {
		cmd = "px 0x200";
		render (core, 0);
		for (;cmd;) {
			int k = sdl_gamepad ();
			if (k == -1) {
				break;
			}
			if (k) {
				render (core, k);
			}
		}
		sdl_fini ();
	}
}

static int r_cmd_gamepad_call(void *user, const char *input) {
	RCore *core = (RCore *) user;
	if (!strcmp (input, "god mode on")) {
		visual_gamepad (core);
		return true;
	}
	return false;
}

RCorePlugin r_core_plugin_gamepad = {
	.name = "gamepad",
	.desc = "",
	.license = "MIT",
	.call = r_cmd_gamepad_call,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_gamepad,
	.version = R2_VERSION
};
#endif

