// doom port for radare2 based on the flipper zero one
// -- pancake

#include <r_cons.h>
#include <stdlib.h>
#include <math.h>
#include <sys/time.h>
#include "display.h"
#include "compiled/assets_icons.c"
#include "constants.h"
#include "entities.h"
#include "types.h"
#include "level.h"

#define REALTIME 1

int SCREEN_WIDTH = 128;
int SCREEN_HEIGHT = 64;
int HALF_WIDTH = 64;
int RENDER_HEIGHT = 56; // raycaster working height (the rest is for the hud)
int HALF_HEIGHT = 32;

// Useful macros
#define swap(a, b) do { typeof(a) temp = a; a = b; b = temp; } while (0)
#define sign(a, b) (double) (a > b ? 1 : (b > a ? -1 : 0))
#define pgm_read_byte(addr) (*(const unsigned char *)(addr))

int tick(void) {
	static int t = 0;
	return ++t;
}

typedef struct {
	Player player;
	Entity entity[MAX_ENTITIES];
	StaticEntity static_entity[MAX_STATIC_ENTITIES];
	uint8_t num_entities;
	uint8_t num_static_entities;

	uint8_t scene;
	uint8_t gun_pos;
	double jogging;
	double view_height;
	bool init;

	bool up;
	bool down;
	bool left;
	bool right;
	bool strife;
	bool strife_left;
	bool strife_right;
	bool fired;
	bool gun_fired;
	bool exit;

	double rot_speed;
	double old_dir_x;
	double old_plane_x;
} PluginState;

static Coords translateIntoView(Coords *pos, PluginState* const ps);
void updateHud(Canvas* const canvas, PluginState* const ps);
void updateEntities(uint8_t level[], Canvas* const canvas, PluginState* const ps);

static bool invert_screen = false;
static bool flash_screen = false;

void setBlockAt(uint8_t level[], int x, int y, char ch) {
	if (x < 0 || x >= LEVEL_WIDTH || y < 0 || y >= LEVEL_HEIGHT) {
		return;
	}
	int nibble = x % 2;
	uint8_t *data = (level + (((LEVEL_HEIGHT - 1 - y) * LEVEL_WIDTH + x) / 2));
	if (nibble) {
		uint8_t v = *data;
		v &= 0xf0;
		v |= ch;
		*data = v;
	} else {
		uint8_t v = *data;
		v &= 0x0f;
		v |= (ch << 4);
		*data = v;
	}
}

uint8_t getBlockAt(const uint8_t level[], int x, int y) {
	if (x < 0 || x >= LEVEL_WIDTH || y < 0 || y >= LEVEL_HEIGHT) {
		return E_FLOOR;
	}

	// y is read in inverse order
	return pgm_read_byte(level + (((LEVEL_HEIGHT - 1 - y) * LEVEL_WIDTH + x) / 2))
		>> (!(x % 2) * 4)       // displace part of wanted bits
		& 0b1111;               // mask wanted bits
}

// Finds the player in the map
void initializeLevel(const uint8_t level[], PluginState* const ps) {
	for (int y = LEVEL_HEIGHT - 1; y > 0; y--) {
		for (int x = 0; x < LEVEL_WIDTH; x++) {
			uint8_t block = getBlockAt(level, x, y);
			if (block == E_PLAYER) {
				ps->player = create_player(x, y);
				printf ("PLAYER AT %d %d\n", x, y);
				return;
			}
			// todo create other static entities
		}
	}
}

static bool isSpawned(UID uid, PluginState* const ps) {
	for (int i = 0; i < ps->num_entities; i++) {
		if (ps->entity[i].uid == uid) return true;
	}
	return false;
}

#if 0
static bool isStatic(UID uid, PluginState* const ps) {
	for (uint8_t i = 0; i < ps->num_static_entities; i++) {
		if (ps->static_entity[i].uid == uid) return true;
	}
	return false;
}
#endif

static void spawnEntity(uint8_t type, int x, int y, PluginState* const ps) {
	// Limit the number of spawned entities
	if (ps->num_entities >= MAX_ENTITIES) {
		return;
	}
	// todo: read static entity status
	switch (type) {
	case E_EXIT:
		ps->entity[ps->num_entities] = create_exit(x, y);
		ps->num_entities++;
		break;
	case E_DOOR:
		ps->entity[ps->num_entities] = create_door(x, y);
		ps->num_entities++;
		break;
	case E_LOCKEDDOOR:
		ps->entity[ps->num_entities] = create_lockeddoor(x, y);
		ps->num_entities++;
		break;
	case E_ENEMY:
		ps->entity[ps->num_entities] = create_enemy(x, y);
		ps->num_entities++;
		break;
	case E_KEY:
		ps->entity[ps->num_entities] = create_key(x, y);
		ps->num_entities++;
		break;
	case E_MEDIKIT:
		ps->entity[ps->num_entities] = create_medikit(x, y);
		ps->num_entities++;
		break;
	}
}

static void spawnFireball(double x, double y, PluginState* const ps) {
	// Limit the number of spawned entities
	if (ps->num_entities >= MAX_ENTITIES) {
		return;
	}

	UID uid = create_uid (E_FIREBALL, x, y);
	// Remove if already exists, don't throw anything. Not the best, but shouldn't happen too often
	if (isSpawned(uid, ps)) return;

	// Calculate direction. 32 angles
	int16_t dir = FIREBALL_ANGLES + atan2(y - ps->player.pos.y, x - ps->player.pos.x) / (double)PI * FIREBALL_ANGLES;
	if (dir < 0) dir += FIREBALL_ANGLES * 2;
	ps->entity[ps->num_entities] = create_fireball (x, y, dir);
	ps->num_entities++;
}

static void removeEntity(UID uid, PluginState* const ps) {
	uint8_t i = 0;
	bool found = false;

	while (i < ps->num_entities) {
		if (!found && ps->entity[i].uid == uid) {
			// todo: doze it
			found = true;
			ps->num_entities--;
		}
		// displace entities
		if (found) {
			ps->entity[i] = ps->entity[i + 1];
		}
		i++;
	}
}

void removeStaticEntity(UID uid, PluginState* const ps) {
	uint8_t i = 0;
	bool found = false;

	while (i < ps->num_static_entities) {
		if (!found && ps->static_entity[i].uid == uid) {
			found = true;
			ps->num_static_entities--;
		}
		// displace entities
		if (found) {
			ps->static_entity[i] = ps->static_entity[i + 1];
		}
		i++;
	}
}

static UID detectCollision(uint8_t level[], Coords *pos, double relative_x, double relative_y, bool only_walls, PluginState* const ps) {
	// Wall collision
	int round_x = (int)(pos->x + relative_x);
	int round_y = (int)(pos->y + relative_y);
	uint8_t block = getBlockAt (level, round_x, round_y);

	if (block == E_WALL) {
		//playSound(hit_wall_snd, HIT_WALL_SND_LEN);
		return create_uid (block, round_x, round_y);
	}
	if (block == E_EXIT) {
		ps->exit = true;
		return UID_null;
	}
	if (block == E_LOCKEDDOOR) {
		if (ps->player.keys > 0) {
			ps->player.keys --;
			// check if enough keys
			setBlockAt (level, round_x, round_y, E_DOOR);
		}
		return create_uid (block, round_x, round_y);
			// ps->entity[i].uid = E_DOOR;
			// return ps->entity[i].uid;
	}

	if (only_walls) {
		return UID_null;
	}

	// Entity collision
	for (int i = 0; i < ps->num_entities; i++) {
		// Don't collide with itself
		if (&(ps->entity[i].pos) == pos) {
			continue;
		}

		uint8_t type = uid_get_type(ps->entity[i].uid);

		// Only ALIVE enemy collision
		if (type != E_ENEMY || ps->entity[i].state == S_DEAD || ps->entity[i].state == S_HIDDEN) {
			continue;
		}

		Coords new_coords = { ps->entity[i].pos.x - relative_x, ps->entity[i].pos.y - relative_y };
		double distance = coords_distance(pos, &new_coords);

		// Check distance and if it's getting closer
		if (distance < ENEMY_COLLIDER_DIST && distance < ps->entity[i].distance) {
			return ps->entity[i].uid;
		}
	}

	return UID_null;
}

// Shoot
void fire(PluginState* const ps) {
	//playSound(shoot_snd, SHOOT_SND_LEN);
	for (int i = 0; i < ps->num_entities; i++) {
		// Shoot only ALIVE enemies
		uint8_t type = uid_get_type (ps->entity[i].uid);
		if (type != E_ENEMY || ps->entity[i].state == S_DEAD || ps->entity[i].state == S_HIDDEN) {
			if (type == E_LOCKEDDOOR) {
				removeEntity(ps->entity[i].uid, ps);
			eprintf ("Bisdaf %d\n", type);
			sleep(1);
			}
			continue;
		}
		Coords transform = translateIntoView (&(ps->entity[i].pos), ps);
		if (fabs (transform.x) < 20 && transform.y > 0) {
			double distance_div = (fabs(transform.x) * ps->entity[i].distance) / 5;
			double damage = (double) fmin (GUN_MAX_DAMAGE, GUN_MAX_DAMAGE / distance_div);
			if (damage > 0) {
				ps->entity[i].health -= damage;
				ps->entity[i].state = S_HIT;
				ps->entity[i].timer = 4;
			}
		}
	}
}

UID updatePosition(uint8_t level[], Coords *pos, double relative_x, double relative_y, bool only_walls, PluginState* const ps) {
	UID collide_x = detectCollision (level, pos, relative_x, 0, only_walls, ps);
	UID collide_y = detectCollision (level, pos, 0, relative_y, only_walls, ps);
	if (!collide_x) pos->x += relative_x;
	if (!collide_y) pos->y += relative_y;
	return collide_x || collide_y || UID_null;
}

void updateEntities(uint8_t level[], Canvas* const canvas, PluginState* const ps) {
	uint8_t i = 0;
	while (i < ps->num_entities) {
		// update distance
		ps->entity[i].distance = coords_distance(&(ps->player.pos), &(ps->entity[i].pos));

		// Run the timer. Works with actual frames.
		// Todo: use delta here. But needs double type and more memory
		if (ps->entity[i].timer > 0) {
			 ps->entity[i].timer--;
		}

		// too far away. put it in doze mode
		if (ps->entity[i].distance > MAX_ENTITY_DISTANCE) {
			removeEntity(ps->entity[i].uid, ps);
			// don't increase 'i', since current one has been removed
			continue;
		}

		// bypass render if hidden
		if (ps->entity[i].state == S_HIDDEN) {
			i++;
			continue;
		}

		uint8_t type = uid_get_type(ps->entity[i].uid);

		switch (type) {
		case E_EXIT:
			// do nothing
			break;
		case E_ENEMY:
		      // Enemy "IA"
		      if (ps->entity[i].health <= 0) {
			      if (ps->entity[i].state != S_DEAD) {
				      ps->entity[i].state = S_DEAD;
				      ps->entity[i].timer = 6;
			      }
		      } else  if (ps->entity[i].state == S_HIT) {
			      if (ps->entity[i].timer == 0) {
				      // Back to alert state
				      ps->entity[i].state = S_ALERT;
				      ps->entity[i].timer = 15;     // delay next fireball thrown
			      }
		      } else if (ps->entity[i].state == S_FIRING) {
			      if (ps->entity[i].timer == 0) {
				      // Back to alert state
				      ps->entity[i].state = S_ALERT;
				      ps->entity[i].timer = 15;     // delay next fireball throwm
			      }
		      } else {
			      // ALERT STATE
			      if (ps->entity[i].distance > ENEMY_MELEE_DIST && ps->entity[i].distance < MAX_ENEMY_VIEW) {
				      if (ps->entity[i].state != S_ALERT) {
					      ps->entity[i].state = S_ALERT;
					      ps->entity[i].timer = 15;   // used to throw fireballs
				      } else {
					      if (ps->entity[i].timer == 0) {
						      // Throw a fireball
						      spawnFireball (ps->entity[i].pos.x, ps->entity[i].pos.y, ps);
						      ps->entity[i].state = S_FIRING;
						      ps->entity[i].timer = 3;
					      } else {
						      // move towards to the player.
						      updatePosition(
								      level,
								      &(ps->entity[i].pos),
								      sign(ps->player.pos.x, ps->entity[i].pos.x) * (double)ENEMY_SPEED * 1, // NOT SURE (delta)
								      sign(ps->player.pos.y, ps->entity[i].pos.y) * (double)ENEMY_SPEED * 1, // NOT SURE (delta)
								      true,
								      ps
								    );
					      }
				      }
			      } else if (ps->entity[i].distance <= ENEMY_MELEE_DIST) {
				      if (ps->entity[i].state != S_MELEE) {
					      // Preparing the melee attack
					      ps->entity[i].state = S_MELEE;
					      ps->entity[i].timer = 10;
				      } else if (ps->entity[i].timer == 0) {
					      // Melee attack
					      ps->player.health = fmax(0, ps->player.health - ENEMY_MELEE_DAMAGE);
					      ps->entity[i].timer = 14;
					      flash_screen = true;
					      updateHud(canvas, ps);
				      }
			      } else {
				      // stand
				      ps->entity[i].state = S_STAND;
			      }
		      }
		      break;
		case E_FIREBALL:
			if (ps->entity[i].distance < FIREBALL_COLLIDER_DIST) {
				// Hit the player and disappear
				ps->player.health = fmax(0, ps->player.health - ENEMY_FIREBALL_DAMAGE);
				flash_screen = true;
				updateHud(canvas, ps);
				removeEntity(ps->entity[i].uid, ps);
				continue; // continue in the loop
			} else {
				// Move. Only collide with walls.
				// Note: using health to store the angle of the movement
				UID collided = updatePosition (
					      level, &(ps->entity[i].pos),
					      cos ((double) ps->entity[i].health / FIREBALL_ANGLES * (double)PI) * (double)FIREBALL_SPEED,
					      sin ((double) ps->entity[i].health / FIREBALL_ANGLES * (double)PI) * (double)FIREBALL_SPEED,
					      true, ps);
				if (collided) {
				      removeEntity (ps->entity[i].uid, ps);
				      continue; // continue in the entity check loop
				}
			}
			break;
		case E_MEDIKIT:
			      if (ps->entity[i].distance < ITEM_COLLIDER_DIST) {
				// pickup
				//playSound(medkit_snd, MEDKIT_SND_LEN);
				ps->entity[i].state = S_HIDDEN;
				ps->player.health = fmin (100, ps->player.health + 50);
				updateHud (canvas, ps);
				flash_screen = 1;
			}
			break;
		case E_KEY:
			if (ps->entity[i].distance < ITEM_COLLIDER_DIST) {
				// pickup
				//playSound(get_key_snd, GET_KEY_SND_LEN);
				ps->entity[i].state = S_HIDDEN;
				ps->player.keys++;
				updateHud (canvas, ps);
				flash_screen = 1;
			}
			break;
		}

		i++;
	}
}

// The map raycaster. Based on https://lodev.org/cgtutor/raycasting.html
void renderMap(const uint8_t level[], double view_height, Canvas* const canvas, PluginState* const ps) {
	UID last_uid = 0; // NOT SURE ?
	int x;

	bool first = true;
	for (x = 0; x < SCREEN_WIDTH; x += RES_DIVIDER) {
		double camera_x = 2 * (double) x / SCREEN_WIDTH - 1;
		double ray_x = ps->player.dir.x + ps->player.plane.x * camera_x;
		double ray_y = ps->player.dir.y + ps->player.plane.y * camera_x;
		uint8_t map_x = (uint8_t)ps->player.pos.x;
		uint8_t map_y = (uint8_t)ps->player.pos.y;
		Coords map_coords = { ps->player.pos.x, ps->player.pos.y };
		double delta_x = fabs(1 / ray_x);
		double delta_y = fabs(1 / ray_y);

		int8_t step_x;
		int8_t step_y;
		double side_x;
		double side_y;

		if (ray_x < 0) {
			step_x = -1;
			side_x = (ps->player.pos.x - map_x) * delta_x;
		} else {
			step_x = 1;
			side_x = (map_x + (double)1.0 - ps->player.pos.x) * delta_x;
		}

		if (ray_y < 0) {
			step_y = -1;
			side_y = (ps->player.pos.y - map_y) * delta_y;
		} else {
			step_y = 1;
			side_y = (map_y + (double)1.0 - ps->player.pos.y) * delta_y;
		}

		// Wall detection
		uint8_t depth = 0;
		bool hit = 0;
		bool side;
		int isdoor = false;
		int isexit = false;
		while (!hit && depth < MAX_RENDER_DEPTH) {
			if (side_x < side_y) {
				side_x += delta_x;
				map_x += step_x;
				side = 0;
			} else {
				side_y += delta_y;
				map_y += step_y;
				side = 1;
			}

			uint8_t block = getBlockAt (level, map_x, map_y);

			if (block == E_LOCKEDDOOR) {
				hit = 1;
				isdoor = true;
			} else if (block == E_EXIT) {
				hit = 1;
				isexit = true;
			} else if (block == E_DOOR) {
				isdoor = true;
			} else if (block == E_WALL) {
				isdoor = false;
				// render a wall if hit
				hit = 1;
			} else {
				// Spawning entities here, as soon they are visible for the
				isdoor = false;
				// player. Not the best place, but would be a very performance
				// cost scan for them in another loop
				if (block == E_ENEMY || (block & 0b00001000) /* all collectable items */) {
					// Check that it's close to the player
					if (coords_distance (&(ps->player.pos), &map_coords) < MAX_ENTITY_DISTANCE) {
						UID uid = create_uid (block, map_x, map_y);
						if (last_uid != uid && !isSpawned (uid, ps)) {
							spawnEntity (block, map_x, map_y, ps);
							last_uid = uid;
						}
					}
				}
			}
			depth++;
		}

		if (hit) {
			double distance;

			if (side == 0) {
				distance = fmax (1, (map_x - ps->player.pos.x + (1 - step_x) / 2) / ray_x);
			} else {
				distance = fmax (1, (map_y - ps->player.pos.y + (1 - step_y) / 2) / ray_y);
			}

			// store zbuffer value for the column
			zbuffer[x / Z_RES_DIVIDER] = fmin(distance * DISTANCE_MULTIPLIER, 255);

			// rendered line height
			uint8_t line_height = RENDER_HEIGHT / distance;
#if 0
			int y = (view_height / distance) - line_height / 2 + RENDER_HEIGHT / 2;
			int y2 = (view_height / distance) + line_height / 2 + RENDER_HEIGHT / 2;
			for (y = y; y <= y2; y ++) {
				canvas_draw_dot(canvas, x, y, '-');
			}
#else
			if (isexit) {
				if (first) {
					r_cons_gotoxy (x, 3);
					r_cons_printf ("exit");
					first = false;
				}
				r_cons_printf (Color_GREEN);
			} else if (isdoor) {
				if (hit) {
					if (first) {
						r_cons_gotoxy (x, 3);
						r_cons_printf ("locked door");
						first = false;
					}
					r_cons_printf (Color_YELLOW);
				}
			}
			drawVLine(
					x,
					view_height / distance - line_height / 2 + RENDER_HEIGHT / 2,
					view_height / distance + line_height / 2 + RENDER_HEIGHT / 2,
					GRADIENT_COUNT - (int)distance / MAX_RENDER_DEPTH * GRADIENT_COUNT - side * 2,
					canvas);
			if (isexit) {
				r_cons_printf ("\x1b[0m");
			} else if (isdoor) {
				if (hit) {
					r_cons_printf ("\x1b[0m");
				}
			}
#endif
		} else {
			if (isdoor) {
				double distance;

				if (side == 0) {
					distance = fmax (1, (map_x - ps->player.pos.x + (1 - step_x) / 2) / ray_x);
				} else {
					distance = fmax (1, (map_y - ps->player.pos.y + (1 - step_y) / 2) / ray_y);
				}
				uint8_t line_height = 2;
				r_cons_printf (Color_YELLOW);
				drawVLine(
						x,
						view_height / distance - line_height / 2 + RENDER_HEIGHT / 2,
						view_height / distance + line_height / 2 + RENDER_HEIGHT / 2,
						GRADIENT_COUNT - (int)distance / MAX_RENDER_DEPTH * GRADIENT_COUNT - side * 2,
						canvas);
				r_cons_printf ("\x1b[0m");
			}
		}
	}
}

// Sort entities from far to close
static uint8_t sortEntities(PluginState* const ps) {
	uint8_t gap = ps->num_entities;
	bool swapped = false;
	while (gap > 1 || swapped) {
		//shrink factor 1.3
		gap = (gap * 10) / 13;
		if (gap == 9 || gap == 10) gap = 11;
		if (gap < 1) gap = 1;
		swapped = false;
		for (int i = 0; i < ps->num_entities - gap; i++) {
			uint8_t j = i + gap;
			if (ps->entity[i].distance < ps->entity[j].distance) {
				swap(ps->entity[i], ps->entity[j]);
				swapped = true;
			}
		}
	}
	return swapped;
}

static Coords translateIntoView(Coords *pos, PluginState* const ps) {
	//translate sprite position to relative to camera
	double sprite_x = pos->x - ps->player.pos.x;
	double sprite_y = pos->y - ps->player.pos.y;

	//required for correct matrix multiplication
	double inv_det = ((double)1.0 / ((double)ps->player.plane.x * (double)ps->player.dir.y - (double)ps->player.dir.x * (double)ps->player.plane.y));
	double transform_x = inv_det * (ps->player.dir.y * sprite_x - ps->player.dir.x * sprite_y);
	double transform_y = inv_det * (- ps->player.plane.y * sprite_x + ps->player.plane.x * sprite_y); // Z in screen
	Coords res = {transform_x, transform_y};
	return res;
}

void renderEntities(double view_height, Canvas* const canvas, PluginState* const ps) {
	sortEntities (ps);

	for (int i = 0; i < ps->num_entities; i++) {
		if (ps->entity[i].state == S_HIDDEN) continue;

		Coords transform = translateIntoView(&(ps->entity[i].pos), ps);

		// don´t render if behind the player or too far away
		if (transform.y <= (double)0.1 || transform.y > MAX_SPRITE_DEPTH) {
			continue;
		}

		int16_t sprite_screen_x = HALF_WIDTH * ((double)1.0 + transform.x / transform.y);
		int8_t sprite_screen_y = RENDER_HEIGHT / 2 + view_height / transform.y;
		uint8_t type = uid_get_type(ps->entity[i].uid);

		// don´t try to render if outside of screen
		// doing this pre-shortcut due int16 -> int8 conversion makes out-of-screen
		// values fit into the screen space
		if (sprite_screen_x < - HALF_WIDTH || sprite_screen_x > SCREEN_WIDTH + HALF_WIDTH) {
			continue;
		}

		switch (type) {
		case E_ENEMY: {
				      uint8_t sprite;
				      if (ps->entity[i].state == S_ALERT) {
					      // walking
					      sprite = (tick() / 500) % 2;
				      } else if (ps->entity[i].state == S_FIRING) {
					      // fireball
					      sprite = 2;
				      } else if (ps->entity[i].state == S_HIT) {
					      // hit
					      sprite = 3;
				      } else if (ps->entity[i].state == S_MELEE) {
					      // melee atack
					      sprite = ps->entity[i].timer > 10 ? 2 : 1;
				      } else if (ps->entity[i].state == S_DEAD) {
					      // dying
					      sprite = ps->entity[i].timer > 0 ? 3 : 4;
				      } else {
					      // stand
					      sprite = 0;
				      }
				      drawSprite (
						      sprite_screen_x - BMP_IMP_WIDTH * (double).5 / transform.y,
						      sprite_screen_y - 8 / transform.y,
						      imp_inv,
						      imp_mask_inv,
						      BMP_IMP_WIDTH,
						      BMP_IMP_HEIGHT,
						      sprite,
						      transform.y,
						      Color_MAGENTA
						);
				      break;
			      }
		case E_FIREBALL:
			 drawSprite (
				 sprite_screen_x - BMP_FIREBALL_WIDTH / 2 / transform.y,
				 sprite_screen_y - BMP_FIREBALL_HEIGHT / 2 / transform.y,
				 fireball, fireball_mask,
				 BMP_FIREBALL_WIDTH,
				 BMP_FIREBALL_HEIGHT,
				 0, transform.y, Color_RED);
			 break;
		case E_DOOR:
			 // never happens
			 sleep(1);
			 drawSprite (sprite_screen_x - BMP_ITEMS_WIDTH / 2 / transform.y,
				sprite_screen_y + 5 / transform.y,
				door, door,
				BMP_ITEMS_WIDTH,
				BMP_ITEMS_HEIGHT,
				0, transform.y, Color_CYAN);
			break;
		case E_MEDIKIT:
			 drawSprite (sprite_screen_x - BMP_ITEMS_WIDTH / 2 / transform.y,
				sprite_screen_y + 5 / transform.y,
				item, item_mask,
				BMP_ITEMS_WIDTH,
				BMP_ITEMS_HEIGHT,
				0, transform.y, Color_CYAN);
			break;
		case E_EXIT:
			// XXX never happens for a reason
			// eprintf ("pintaexi %d\n",3); sleep(1);
			drawSprite (sprite_screen_x - BMP_ITEMS_WIDTH / 2 / transform.y,
				sprite_screen_y + 5 / transform.y,
				item, item_mask,
				BMP_ITEMS_WIDTH,
				BMP_ITEMS_HEIGHT,
				1, transform.y, Color_GREEN);
			break;
		case E_KEY:
			drawSprite (sprite_screen_x - BMP_ITEMS_WIDTH / 2 / transform.y,
				sprite_screen_y + 5 / transform.y,
				item, item_mask,
				BMP_ITEMS_WIDTH,
				BMP_ITEMS_HEIGHT,
				1, transform.y, Color_YELLOW);
			break;
		}
	}
}

void renderGun(int gun_pos, double amount_jogging, Canvas* const canvas) {
	// jogging
	int t = tick ();
	int gx = SCREEN_WIDTH / 3;
	int x = gx + sin((double) t * (double)JOGGING_SPEED) * 10 * amount_jogging;
	int y = RENDER_HEIGHT - gun_pos + fabs (cos ((double) t * (double)JOGGING_SPEED)) * 8 * amount_jogging;

	bool onfire = false;
	if (gun_pos > GUN_SHOT_POS - 2) {
		// Gun fire
		onfire = true;
		r_cons_printf(Color_RED);
		drawBitmap (x + 6, y - 11, &I_fire_inv, BMP_FIRE_WIDTH, BMP_FIRE_HEIGHT, 1, canvas);
		r_cons_printf("\x1b[0m");
	}

	// Don't draw over the hud!
	uint8_t clip_height = fmax(0, fmin(y + BMP_GUN_HEIGHT, RENDER_HEIGHT) - y);

	clip_height+=2;
	// Draw the gun (black mask + actual sprite).
	drawBitmap(x, y, &I_gun_mask_inv, BMP_GUN_WIDTH, clip_height, 0, canvas);
	drawBitmap(x, y, &I_gun_inv, BMP_GUN_WIDTH, clip_height, 1, canvas);
	if (onfire) {
		drawGun(x,y,gun_mask, BMP_GUN_WIDTH, clip_height, 0, Color_RED);
		drawGun(x,y,gun, BMP_GUN_WIDTH, clip_height, 1, Color_WHITE);
	} else {
		drawGun(x,y,gun_mask, BMP_GUN_WIDTH, clip_height, 0, Color_BLUE);
		drawGun(x,y,gun, BMP_GUN_WIDTH, clip_height, 1, Color_CYAN);
	}
}

// Only needed first time
void renderHud(Canvas* const canvas, PluginState* ps) {
	int y = RENDER_HEIGHT;
	// clearRect (0, y + 2, SCREEN_WIDTH - 3, SCREEN_HEIGHT-y-2, canvas);
	clearHLines (y, SCREEN_HEIGHT-y);
	// drawRect (0, 57, SCREEN_WIDTH, SCREEN_HEIGHT - 56, canvas); // "-", 0
	////  clearRect (2, 58, SCREEN_WIDTH - 4, 6, canvas);
	// clearRect(2, 58, SCREEN_WIDTH - 4, SCREEN_HEIGHT - 64, canvas); // "-", 0
	r_cons_printf (Color_RED);
	drawTextSpace (2, y + 3, "{}", 0, canvas);        // Health symbol
	r_cons_printf (Color_YELLOW);
	drawTextSpace (40, y + 2, "[]", 0, canvas);       // Keys symbol
	r_cons_printf("\x1b[0m");
	updateHud (canvas, ps);
	drawHLine (0, y + 2, SCREEN_WIDTH, Color_YELLOW);
}

// Render values for the HUD
void updateHud(Canvas* const canvas, PluginState* ps) {
	int y = RENDER_HEIGHT + 2;
	// clearRect (12, y, 15, 6, canvas);
	// clearRect(50, 58, 15, 6, canvas);
	drawText (12, y, ps->player.health, canvas);
	drawText (50, y, ps->player.keys, canvas);
}

// Debug stats
void renderStats(Canvas* const canvas, PluginState* ps) {
	int y = RENDER_HEIGHT+ 2;
	drawText(114, y, (int)getActualFps(), canvas);
	drawText(82, y, ps->num_entities, canvas);
	//drawText(94, 58, freeMemory());
}

// Intro screen
void loopIntro(Canvas* const canvas) {
	// canvas_draw_icon(canvas, (SCREEN_WIDTH - BMP_LOGO_WIDTH) / 2, (SCREEN_HEIGHT - BMP_LOGO_HEIGHT) / 3, &I_logo_inv);
	const char *logo = \
			   "=================     ===============     ===============   ========  ========\n" \
			   "\\\\ . . . . . . .\\\\   //. . . . . . .\\\\   //. . . . . . .\\\\  \\\\. . .\\\\// . . //\n" \
			   "||. . ._____. . .|| ||. . ._____. . .|| ||. . ._____. . .|| || . . .\\/ . . .||\n" \
			   "|| . .||   ||. . || || . .||   ||. . || || . .||   ||. . || ||. . . . . . . ||\n" \
			   "||. . ||   || . .|| ||. . ||   || . .|| ||. . ||   || . .|| || . | . . . . .||\n" \
			   "|| . .||   ||. _-|| ||-_ .||   ||. . || || . .||   ||. _-|| ||-_.|\\ . . . . ||\n" \
			   "||. . ||   ||-'  || ||  `-||   || . .|| ||. . ||   ||-'  || ||  `|\\_ . .|. .||\n" \
			   "|| . _||   ||    || ||    ||   ||_ . || || . _||   ||    || ||   |\\ `-_/| . ||\n" \
			   "||_-' ||  .|/    || ||    \\|.  || `-_|| ||_-' ||  .|/    || ||   | \\  / |-_.||\n" \
			   "||    ||_-'      || ||      `-_||    || ||    ||_-'      || ||   | \\  / |  `||\n" \
			   "||    `'         || ||         `'    || ||    `'         || ||   | \\  / |   ||\n" \
			   "||            .===' `===.         .==='.`===.         .===' /==. |  \\/  |   ||\n" \
			   "||         .=='   \\_|-_ `===. .==='   _|_   `===. .===' _-|/   `==  \\/  |   ||\n" \
			   "||      .=='    _-'    `-_  `='    _-'   `-_    `='  _-'   `-_  /|  \\/  |   ||\n" \
			   "||   .=='    _-'          `-__\\._-'         `-_./__-'         `' |. /|  |   ||\n" \
			   "||.=='    _-'                                                     `' |  /==.||\n" \
			   "=='    _-'                                                            \\/   `==\n" \
			   "\\   _-'                                                                `-_   /\n" \
			   " `''                                                                      ``'\n" ;
	r_cons_printf ("Press 'Q' to quit\n\n%s\n", logo);

	drawTextSpace (16, SCREEN_HEIGHT - 8, "PRESS FIRE", 1, canvas);
}

static void render_callback(Canvas* const canvas, void* ctx) {
	int h, w = r_cons_get_size (&h);
	SCREEN_WIDTH = w;
	SCREEN_HEIGHT = h+1;
	HALF_WIDTH = w/2;
	HALF_HEIGHT = h/2;
	RENDER_HEIGHT = h - 8;
	PluginState* ps = ctx;
	if (ps == NULL) {
		return;
	}
	r_cons_clear00 ();
#if 1
	if (ps->init) {
		 setupDisplay (canvas);
	}
#endif
	// canvas_set_font(canvas, FontPrimary);
	switch (ps->scene) {
	case INTRO:
		loopIntro (canvas);
		break;
	case GAME_PLAY:
		updateEntities (sto_level_1, canvas, ps);
		updateHud (canvas, ps);
		renderMap (sto_level_1, ps->view_height, canvas, ps);
		renderEntities (ps->view_height, canvas, ps);
		renderHud (canvas, ps);
		renderStats (canvas, ps);
		if (ps->player.health > 0) {
			renderGun (ps->gun_pos, ps->jogging, canvas);
		}
		r_cons_gotoxy (0, 0);
		r_cons_printf ("Press 'Q' to quit");
		r_cons_gotoxy (0, 0);
		break;
	}
#if 0
	r_cons_gotoxy (0,1);
	r_cons_printf ("> %lf %lf %lf v=%lf\n", ps->player.pos.x, ps->player.pos.y, ps->player.dir.x, ps->player.velocity);
#endif
	r_cons_flush ();
}

static void doom_state_init(PluginState* const ps) {
	ps->num_entities = 0;
	ps->num_static_entities = 0;

	ps->scene = INTRO;
	ps->gun_pos = 0;
	ps->view_height = 0;
	ps->init = true;

	ps->up = false;
	ps->down = false;
	ps->left = false;
	ps->right = false;
	ps->fired = false;
	ps->gun_fired = false;
}

static void doom_game_tick(PluginState* const ps) {
	if (display_buf == NULL) {
		display_buf = calloc (SCREEN_WIDTH, SCREEN_HEIGHT);
	}
	if (ps->scene == GAME_PLAY) {
		fps ();
		// player is alive
		if (ps->player.health > 0) {
			if (ps->up) {
				ps->player.velocity += ((double)MOV_SPEED - ps->player.velocity) * (double).4;
				ps->jogging = fabs(ps->player.velocity) * MOV_SPEED_INV;
				// ps->player.pos.x++;
				ps->up = false;
			} else if (ps->down) {
				// ps->player.pos.x--;
				ps->player.velocity += (- (double)MOV_SPEED - ps->player.velocity) * (double).4;
				ps->jogging = fabs(ps->player.velocity) * MOV_SPEED_INV;
				ps->down = false;
			} else {
				ps->player.velocity *= (double).5;
				ps->jogging = fabs (ps->player.velocity) * MOV_SPEED_INV;
			}
			if (ps->strife_left) {
				ps->player.velocity -= ((double)MOV_SPEED - ps->player.velocity) * (double).4;
				ps->strife = true;
				ps->strife_left = false;
			} else if (ps->strife_right) {
				ps->player.velocity += ((double)MOV_SPEED - ps->player.velocity) * (double).4;
				ps->strife = true;
				ps->strife_right = false;
			}
			if (ps->right) {
				ps->rot_speed = (double)ROT_SPEED * delta;
				ps->old_dir_x = ps->player.dir.x;
				ps->player.dir.x = ps->player.dir.x * cos(-(ps->rot_speed)) - ps->player.dir.y * sin(-(ps->rot_speed));
				ps->player.dir.y = ps->old_dir_x * sin(-(ps->rot_speed)) + ps->player.dir.y * cos(-(ps->rot_speed));
				ps->old_plane_x = ps->player.plane.x;
				ps->player.plane.x = ps->player.plane.x * cos(-(ps->rot_speed)) - ps->player.plane.y * sin(-(ps->rot_speed));
				ps->player.plane.y = ps->old_plane_x * sin(-(ps->rot_speed)) + ps->player.plane.y * cos(-(ps->rot_speed));
				ps->right = false;
			} else if (ps->left) {
				ps->rot_speed = (double)ROT_SPEED * delta;
				ps->old_dir_x = ps->player.dir.x;
				ps->player.dir.x = ps->player.dir.x * cos(ps->rot_speed) - ps->player.dir.y * sin(ps->rot_speed);
				ps->player.dir.y = ps->old_dir_x * sin(ps->rot_speed) + ps->player.dir.y * cos(ps->rot_speed);
				ps->old_plane_x = ps->player.plane.x;
				ps->player.plane.x = ps->player.plane.x * cos(ps->rot_speed) - ps->player.plane.y * sin(ps->rot_speed);
				ps->player.plane.y = ps->old_plane_x * sin(ps->rot_speed) + ps->player.plane.y * cos(ps->rot_speed);
				ps->left = false;
			}
			ps->view_height = fabs (sin ((double) tick() * (double)JOGGING_SPEED)) * 6 * ps->jogging;

			if (ps->gun_pos > GUN_TARGET_POS) {
				ps->gun_pos -= 1;
			} else if (ps->gun_pos < GUN_TARGET_POS) {
				ps->gun_pos += 2;
			} else if (!ps->gun_fired && ps->fired) {
				ps->gun_pos = GUN_SHOT_POS;
				ps->gun_fired = true;
				fire (ps);
				ps->fired = false;
			} else if (ps->gun_fired) { // && !ps->fired) {
				ps->gun_fired = false;
				ps->fired = false;
			}
		} else {
			// Player is dead
			if (ps->view_height > -10) {
				ps->view_height--;
			}
			if (ps->gun_pos > 1) {
				ps->gun_pos -= 2;
			}
		}
#define STRIFE_DELTA 12
			if (ps->strife) {
				double delta = -STRIFE_DELTA;
				ps->rot_speed = (double)ROT_SPEED * delta;
				ps->old_dir_x = ps->player.dir.x;
				ps->player.dir.x = ps->player.dir.x * cos(ps->rot_speed) - ps->player.dir.y * sin(ps->rot_speed);
				ps->player.dir.y = ps->old_dir_x * sin(ps->rot_speed) + ps->player.dir.y * cos(ps->rot_speed);
				ps->old_plane_x = ps->player.plane.x;
				ps->player.plane.x = ps->player.plane.x * cos(ps->rot_speed) - ps->player.plane.y * sin(ps->rot_speed);
				ps->player.plane.y = ps->old_plane_x * sin(ps->rot_speed) + ps->player.plane.y * cos(ps->rot_speed);
				// sleep(1);
			}
		if (fabs (ps->player.velocity) > (double)0.003) {
			updatePosition (sto_level_1, &(ps->player.pos),
				ps->player.dir.x * ps->player.velocity * delta,
				ps->player.dir.y * ps->player.velocity * delta,
				false, ps);
		} else {
			ps->player.velocity = 0;
		}
			if (ps->strife) {
				// sleep(1);
				ps->strife = false;
				double delta = STRIFE_DELTA;
				ps->rot_speed = (double)ROT_SPEED * delta;
				ps->old_dir_x = ps->player.dir.x;
				ps->player.dir.x = ps->player.dir.x * cos(ps->rot_speed) - ps->player.dir.y * sin(ps->rot_speed);
				ps->player.dir.y = ps->old_dir_x * sin(ps->rot_speed) + ps->player.dir.y * cos(ps->rot_speed);
				ps->old_plane_x = ps->player.plane.x;
				ps->player.plane.x = ps->player.plane.x * cos(ps->rot_speed) - ps->player.plane.y * sin(ps->rot_speed);
				ps->player.plane.y = ps->old_plane_x * sin(ps->rot_speed) + ps->player.plane.y * cos(ps->rot_speed);
			}
	}
}

// nokia
#if 0
http://zserge.com/nokia-composer/#eyJicG0iOiIxMjAiLCJzb25nIjoiYyBkIGUgZiBnIGEgYiJ9
DO RE MI FA SOL LA SI
 c  d  e  f   g  a  b


#endif

int main() {
	sto_level_1 = sto_level_1_orig;
	char *map = r_file_slurp ("map.txt", NULL);
	if (map) {
		sto_level_1 = parse_map (map);
	}
	PluginState ps = {0};
	doom_state_init (&ps);
	static const char music[] = \
		    "Doom:d=32,o=4,b=56:f,f,f5,f,f,d#5,f,f,c#5,f,f,b,f,f,c5,c#5,f,f,f5,f,f,d#5,f,f," \
		    "c#5,f,f,8b.,f,f,f5,f,f,d#5,f,f,c#5,f,f,b,f,f,c5,c#5,f,f,f5,f,f,d#5,f,f,c#5,f,f," \
		    "8b.,a#,a#,a#5,a#,a#,g#5,a#,a#,f#5,a#,a#,e5,a#,a#,f5,f#5,a#,a#,a#5,a#,a#,g#5,a#,a#,f#5,a#,a#,8e5";
	r_cons_new ();
	r_cons_show_cursor (false);
	r_cons_set_raw (true);
	while (true) {
		render_callback (NULL, &ps);
		// 1000 = 1s
#if REALTIME
		int ch = r_cons_readchar_timeout (300);
#else
		int ch = r_cons_readchar ();
#endif
		ch = r_cons_arrow_to_hjkl (ch);
		if (ps.exit || ch == 'Q') {
			if (ps.scene == INTRO) {
				break;
			}
			ps.exit = false;
			ps.scene = INTRO;
			ps.fired = false;
		}
		switch (ch) {
		case 'f':
		case '.':
		case ' ':
		case '\n':
			if (ps.scene == GAME_PLAY) {
				ps.fired = true;
			} else {
				ps.scene = GAME_PLAY;
				ps.player.health = 100;
				initializeLevel (sto_level_1, &ps);
			}
			break;
		case 'q':
			ps.strife_left = true;
			break;
		case 'e':
			ps.strife_right = true;
			break;
		case 's':
		case 'j':
			ps.down = true;
			break;
		case 'w':
		case 'k':
			ps.up = true;
			break;
		case 'd':
		case 'l':
			ps.right = true;
			break;
		case 'a':
		case 'h':
			ps.left = true;
			break;
		}
		doom_game_tick (&ps);
	}
	r_cons_set_raw (false);
}
