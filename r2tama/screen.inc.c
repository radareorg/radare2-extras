/* radare2 - LGPL-3.0-only - Copyright 2026 - pancake */

#include "icons.inc.c"

static void tama_screen_pixel(ut8 *screen, int x, int y, ut8 value) {
	memset (screen + (y * TAMA_SCREEN_WIDTH + x) * 3, value, 3);
}

static void tama_screen_border(ut8 *screen, int x, int y, int width, int height, ut8 value) {
	int i;
	for (i = 0; i < width; i++) {
		tama_screen_pixel (screen, x + i, y, value);
		tama_screen_pixel (screen, x + i, y + height - 1, value);
	}
	for (i = 0; i < height; i++) {
		tama_screen_pixel (screen, x, y + i, value);
		tama_screen_pixel (screen, x + width - 1, y + i, value);
	}
}

static void tama_screen_render(RCoreTama *tama, const ut8 *matrix) {
	ut8 screen[TAMA_SCREEN_SIZE] = {0};
	int icon, x, y;
	for (icon = 0; icon < 8; icon++) {
		bool selected = (tama->icons >> icon) & 1;
		int left = (icon % 4) * 32, top = icon < 4? 0: 74;
		for (y = 0; y < 18; y++) {
			for (x = 0; x < 22; x++) {
				if ((tama_icon_pixels[icon][y] >> x) & 1) {
					tama_screen_pixel (screen, left + 5 + x, top + 2 + y, selected? 255: 112);
				}
			}
		}
		if (selected) {
			tama_screen_border (screen, left + 3, top, 26, 22, 255);
		}
	}
	tama_screen_border (screen, 14, 22, 100, 52, 112);
	for (y = 0; y < 48; y++) {
		for (x = 0; x < 96; x++) {
			tama_screen_pixel (screen, 16 + x, 24 + y, matrix[((y / 3) * 32 + x / 3) * 3]);
		}
	}
	r_io_fd_write_at (tama->io, tama->screen_fd, 0, screen, sizeof (screen));
}

static char *tama_screen_image(RCoreTama *tama) {
	ut8 pixels[TAMA_SCREEN_SIZE];
	r_io_fd_read_at (tama->io, tama->screen_fd, 0, pixels, sizeof (pixels));
	int color = r_config_get_i (tama->core->config, "scr.color");
	return r_cons_image (pixels, sizeof (pixels), TAMA_SCREEN_WIDTH, color >= 3? 'r': color == 2? '2': color == 1? 'A': 'a', 3);
}

static char *tama_screen_fit(RCoreTama *tama, int cols, int rows) {
	ut8 pixels[TAMA_SCREEN_SIZE], scaled[TAMA_SCREEN_WIDTH * TAMA_SCREEN_HEIGHT];
	r_io_fd_read_at (tama->io, tama->screen_fd, 0, pixels, sizeof (pixels));
	int width = R_MIN (cols, TAMA_SCREEN_WIDTH / 2) * 2;
	int height = R_MIN (rows, TAMA_SCREEN_HEIGHT / 4) * 4;
	if (width * TAMA_SCREEN_HEIGHT < height * TAMA_SCREEN_WIDTH) {
		height = width * TAMA_SCREEN_HEIGHT / TAMA_SCREEN_WIDTH;
	} else {
		width = height * TAMA_SCREEN_WIDTH / TAMA_SCREEN_HEIGHT;
	}
	width = R_MAX (2, width & ~1);
	height = R_MAX (4, height & ~3);
	int x, y;
	for (y = 0; y < height; y++) {
		for (x = 0; x < width; x++) {
			int x0 = x * TAMA_SCREEN_WIDTH / width, x1 = (x + 1) * TAMA_SCREEN_WIDTH / width;
			int y0 = y * TAMA_SCREEN_HEIGHT / height, y1 = (y + 1) * TAMA_SCREEN_HEIGHT / height;
			int sum = 0, sx, sy;
			for (sy = y0; sy < y1; sy++) {
				for (sx = x0; sx < x1; sx++) {
					sum += pixels[(sy * TAMA_SCREEN_WIDTH + sx) * 3];
				}
			}
			scaled[y * width + x] = sum / ((x1 - x0) * (y1 - y0));
		}
	}
	static const int dots[8] = { _BR00, _BR01, _BR10, _BR11, _BR20, _BR21, _BR30, _BR31 };
	bool color = r_config_get_i (tama->core->config, "scr.color") > 0;
	RStrBuf out;
	r_strbuf_init (&out);
	for (y = 0; y < height; y += 4) {
		for (x = 0; x < width; x += 2) {
			int bits = 0, light = 0, i;
			for (i = 0; i < 8; i++) {
				ut8 value = scaled[(y + i / 2) * width + x + i % 2];
				if (value >= 40) {
					bits |= dots[i];
					light = R_MAX (light, value);
				}
			}
			if (color) {
				RColor pair = { .a = ALPHA_FGBG, .r = light, .g = light, .b = light, .id16 = -1 };
				char sequence[128];
				r_cons_rgb_str (tama->core->cons, sequence, sizeof (sequence), &pair);
				r_strbuf_append (&out, sequence);
			}
			RBraile cell = r_print_braile (bits);
			r_strbuf_append (&out, cell.str);
		}
		r_strbuf_append (&out, color? Color_RESET"\n": "\n");
	}
	return r_strbuf_drain_nofree (&out);
}

static char *tama_screen(RCoreTama *tama) {
	int rows;
	int cols = r_cons_get_size (tama->core->cons, &rows);
	if (cols >= TAMA_SCREEN_WIDTH && rows >= TAMA_SCREEN_HEIGHT / 2 + 2) {
		return tama_screen_image (tama);
	}
	return tama_screen_fit (tama, R_MAX (1, cols), R_MAX (1, rows - 2));
}
