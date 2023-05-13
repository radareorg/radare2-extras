#ifndef _types_h
#define _types_h

#include <stdint.h>
#include <math.h>

#define UID_null  0

// Entity types (legend applies to level.h)
#define E_FLOOR             0x0   // . (also null)
#define E_WALL              0xF   // #
#define E_PLAYER            0x1   // P
#define E_ENEMY             0x2   // E
#define E_DOOR              0x4   // D
#define E_LOCKEDDOOR        0x5   // L
#define E_EXIT              0x7   // X
// collectable entities >= 0x8
#define E_MEDIKIT           0x8   // M
#define E_KEY               0x9   // K
#define E_FIREBALL          0xA   // not in map

typedef uint16_t UID;
typedef uint8_t  EType;

typedef struct Coords {
	double x;
	double y;
} Coords;

static inline double sq(double val){
	return val * val;
}

static inline Coords create_coords(double x, double y) {
	Coords cord;
	cord.x = x;
	cord.y = y;
	return cord;
}

static inline double coords_distance(Coords* a, Coords* b) {
	return sqrt(sq(a->x - b->x) + sq(a->y - b->y)) * 20;
}

static inline UID create_uid(uint8_t type, uint8_t x, uint8_t y) {
	return ((y << 6) | x) << 4 | type;
}

static inline uint8_t uid_get_type(UID uid) {
	return uid & 0x0F;
}
#endif

