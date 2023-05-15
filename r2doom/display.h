#if 0
#include <gui/gui.h>
#include <furi_hal.h>
#include <u8g2_glue.h>
#endif
#include <r_cons.h>
#include "constants.h"
#include "compiled/assets_icons.h"
// display
// TODO: be dynamic using r_cons_get_size()
extern int SCREEN_WIDTH;
extern int SCREEN_HEIGHT;
extern int HALF_WIDTH;
extern int RENDER_HEIGHT;
extern int HALF_HEIGHT;

#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

static const uint8_t bit_mask[8] = { 128, 64, 32, 16, 8, 4, 2, 1 };


#define pgm_read_byte(addr) (*(const unsigned char *)(addr))
#define read_bit(b, n)      b & pgm_read_byte(bit_mask + n) ? 1 : 0
//#define read_bit(byte, index) (((unsigned)(byte) >> (index)) & 1)

void drawPixel(int x, int y, bool color, bool raycasterViewport, const char *ansi);
void drawBitmap(int x, int y, const Icon *i, int w, int h, uint16_t color, Canvas* const canvas);
void drawTextSpace(int x, int y, char *txt, uint8_t space, Canvas* const canvas);
void drawChar(int x, int y, char ch, Canvas* const canvas);
void clearRect(int x, int y, int w, int h, Canvas* const canvas);
void fadeScreen(uint8_t intensity, bool color, Canvas* const canvas);
bool getGradientPixel(uint8_t x, uint8_t y, uint8_t i);
double getActualFps();
void setupDisplay(Canvas* canvas);
uint8_t reverse_bits(uint8_t num);

// FPS control
double delta = 1;
uint32_t lastFrameTime = 0;
uint8_t zbuffer[128]; /// 128 = screen width & REMOVE WHEN DISPLAY.H IMPLEMENTED
uint8_t *display_buf = NULL;

void drawGun(int x, int y, const uint8_t *bitmap, int w, int h, uint16_t color, const char *ansi) {
	int16_t byteWidth = (w + 7) / 8;
	uint8_t byte = 0;
	for(int16_t j=0; j<h; j++, y++) {
		for(int16_t i=0; i<w; i++) {
			if(i & 7) byte <<= 1;
			else      byte   = pgm_read_byte(&bitmap[j * byteWidth + i / 8]);
			if(byte & 0x80) drawPixel(x+i, y, color,false, ansi);
		}
	}
}

void canvas_draw_dot(int x, int y, char ch) {
	// x/=2;
	// y/=2;
	// r_cons_printf ("(%d/%d)\n", x, y);
	r_cons_gotoxy (x, y);
	r_cons_printf ("%c", ch);
}

void drawVLine(int x, int start_y, int end_y, uint8_t intensity, Canvas* const canvas){
	int dots = end_y - start_y;
	int pc = RENDER_HEIGHT / dots;
	char ch = '#';
	if (pc > 6) {
		ch = '.';
	} else if (pc > 4) {
		ch = '-';
	} else if (pc > 2) {
		ch = '=';
	}
	for(int i = 0; i <= dots; i++) {
		canvas_draw_dot (x, start_y + i, ch);
		canvas_draw_dot (x+1, start_y + i, ch);
	}	
}

void setupDisplay(Canvas* canvas){
	memset(zbuffer, 0xff, 128);
	r_cons_clear00 ();
}

void drawBitmap(int x, int y, const Icon *i, int w, int h, uint16_t color, Canvas* const canvas){
	// canvas_draw_icon_bitmap(canvas, x, y, w, h, i);
}

// this is drawNumber
void drawText(int x, int y, uint8_t num, Canvas* const canvas){
	char buf[4]; // "0" - "255"
	sprintf (buf, "%d", num);
	// itoa(num, buf, 10);
	drawTextSpace (x,y,buf,1,canvas);	
}

void drawTextSpace(int x, int y, char *txt, uint8_t space, Canvas* const canvas){
	int pos = x;
	int i = 0;
	char ch;
	while ((ch = txt[i]) != '\0') {
		drawChar (pos, y, ch, canvas);
		i++;
		pos += CHAR_WIDTH + space;
		if (pos > SCREEN_WIDTH) {
			break;
		}
	}
}

// Custom drawBitmap method with scale support, mask, zindex and pattern filling
void drawSprite(int x, int y, const uint8_t *bitmap, const uint8_t *bitmap_mask, int w, int h, uint8_t sprite, double distance, const char *color) {
	int tw = (double) w / distance;
	int th = (double) h / distance;
	int byte_width = w / 8;
	int pixel_size = fmax(1, (double)1.0 / (double)distance);
	uint16_t sprite_offset = byte_width * h * sprite;

	bool pixel;
	bool maskPixel;

	// Don't draw the whole sprite if the anchor is hidden by z buffer
	// Not checked per pixel for performance reasons
	if (zbuffer[(int)(fmin(fmax(x, 0), ZBUFFER_SIZE - 1) / Z_RES_DIVIDER)] < distance * DISTANCE_MULTIPLIER) {
		return;
	}

	for (int ty = 0; ty < th; ty += pixel_size) {
		// Don't draw out of screen
		if (y + ty < 0 || y + ty >= RENDER_HEIGHT) {
			continue;
		}

		int sy = ty * distance; // The y from the sprite

		for (int tx = 0; tx < tw; tx += pixel_size) {
			int sx = tx * distance; // The x from the sprite
			uint16_t byte_offset = sprite_offset + sy * byte_width + sx / 8;

			// Don't draw out of screen
			if (x + tx < 0 || x + tx >= SCREEN_WIDTH) {
				continue;
			}

			maskPixel = read_bit(pgm_read_byte(bitmap_mask + byte_offset), sx % 8);

			if (maskPixel) {
				pixel = read_bit(pgm_read_byte(bitmap + byte_offset), sx % 8);
				for (int ox = 0; ox < pixel_size; ox++) {
					for (int oy = 0; oy < pixel_size; oy++) {
						if(bitmap == imp_inv)
							drawPixel (x + tx + ox, y + ty + oy, 1, true, color);
						else
							drawPixel (x + tx + ox, y + ty + oy, pixel, true, color);
					}
				}
			}
		}
	}
}

void drawPixel(int x, int y, bool color, bool raycasterViewport, const char *ansi) {
	if (x < 0 || x >= SCREEN_WIDTH || y < 0 || y >= (raycasterViewport ? RENDER_HEIGHT : SCREEN_HEIGHT)){
		return;
	}
	char pixel = color? '#': '+';
	if (ansi) {
		r_cons_gotoxy (x, y);
		r_cons_printf ("%s%c"Color_RESET, ansi, pixel);
		// canvas_draw_dot (canvas, x, y, pixel);
	} else {
		canvas_draw_dot (x, y, pixel);
	}
}

void drawChar(int x, int y, char ch, Canvas* const canvas){
	uint8_t lsb;
	uint8_t c = 0;
	while (CHAR_MAP[c] != ch && CHAR_MAP[c] != '\0') {
		c++;
	}
	for (uint8_t i = 0; i < 6; i++){
		lsb = reverse_bits (char_arr[c][i]);
		for (int n = 0; n < 4; n++){
			if (CHECK_BIT(lsb, n)){
				drawPixel(x+n, y+i, true, false, NULL);
			}    
		}
	}

}

void clearRect(int x, int y, int w, int h, Canvas* const canvas){
	// canvas_invert_color(canvas);
	int i, j;
	for (i = 0; i < w; i++) {
		for (j = 0; j < h; j++) {
			canvas_draw_dot (x + i, y + j, ' ');
		}
	}
	// canvas_invert_color (canvas);
}

void clearHLines(int y, int h) {
	int i;
	for (i = 0; i < h; i++) {
		r_cons_gotoxy (0, y + i);
		r_cons_printf ("%s", R_CONS_CLEAR_LINE);
	}
}

void drawRect(int x, int y, int w, int h, Canvas* const canvas){
	for(int i = 0; i < w; i++) {
		for (int j = 0; j < h; j++){
			canvas_draw_dot (x + i, y + j, '|');
		}
	}
}

void drawHLine (int x, int y, int w, const char *color) {
	char *line = malloc (w + 1);
	memset (line, '-', w - 2);
	line[0] = '.';
	line[w - 2] = '.';
	line[w -1] = 0;
	r_cons_gotoxy (x, y);
	r_cons_printf ("%s", line);
	free (line);
}

#if 0
bool getGradientPixel(uint8_t x, uint8_t y, uint8_t i) {
  if (i == 0) return 0;
  if (i >= GRADIENT_COUNT - 1) return 1;

  uint8_t index = fmax(0, fmin(GRADIENT_COUNT - 1, i)) * GRADIENT_WIDTH * GRADIENT_HEIGHT // gradient index
                  + y * GRADIENT_WIDTH % (GRADIENT_WIDTH * GRADIENT_HEIGHT)             // y byte offset
                  + x / GRADIENT_HEIGHT % GRADIENT_WIDTH;                               // x byte offset
  //uint8_t *gradient_data = NULL;
  //furi_hal_compress_icon_decode(icon_get_data(&I_gradient_inv), &gradient_data);
  // return the bit based on x
  return read_bit(pgm_read_byte(gradient + index), x % 8);
}



void fadeScreen(uint8_t intensity, bool color, Canvas* const canvas) {
  for (uint8_t x = 0; x < SCREEN_WIDTH; x++) {
    for (uint8_t y = 0; y < SCREEN_HEIGHT; y++) {
      if (getGradientPixel(x, y, intensity)) 
        drawPixel(x, y, color, false, canvas);
    }
  }
}
#endif

// Adds a delay to limit play to specified fps
int tick(void);
// Calculates also delta to keep movement consistent in lower framerates
void fps() {
	while (tick() - lastFrameTime < FRAME_TIME);
	delta = (double)(tick() - lastFrameTime) / (double)FRAME_TIME;
	lastFrameTime = tick();
}

double getActualFps() {
	return 1000 / ((double)FRAME_TIME * (double)delta);
}


uint8_t reverse_bits(uint8_t num)
{
	unsigned int NO_OF_BITS = sizeof(num) * 8;
	uint8_t reverse_num = 0;
	uint8_t i;
	for (i = 0; i < NO_OF_BITS; i++) {
		if ((num & (1 << i)))
			reverse_num |= 1 << ((NO_OF_BITS - 1) - i);
	}
	return reverse_num;
}
