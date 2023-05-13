#ifndef sound_h
#define sound_h
#include <m-string.h>
#include <furi.h>
#include <furi_hal.h>
#include <stdint.h>
#include "../music_player/music_player_worker.h"


//static const char dspistol[] = "AnyConv:d=,o=,b=120:408,40p,40p,40p,40p,405,40p,40p,40p,405,30p.,30p.,30p.,13p";
//static const char dsgetpow[] = "dsgetpow:d=,o=,b=120:407,40p,30.6,407,40p,406,40p,407,40p,40p,407,30p.,407";
//static const char dsnoway[] = "dsnoway:d=,o=,b=120:407,30.4";

#define MUSIC_PLAYER_SEMITONE_HISTORY_SIZE 4
static const float MUSIC_PLAYER_VOLUMES[] = {0, .25, .5, .75, 1};

typedef struct {
	uint8_t semitone_history[MUSIC_PLAYER_SEMITONE_HISTORY_SIZE];
	uint8_t duration_history[MUSIC_PLAYER_SEMITONE_HISTORY_SIZE];

	uint8_t volume;
	uint8_t semitone;
	uint8_t dots;
	uint8_t duration;
	float position;
} MusicPlayerModel;

typedef struct {
	MusicPlayerModel* model; 
	MusicPlayerWorker* worker;
	FuriMutex** model_mutex;
} MusicPlayer;


#endif
