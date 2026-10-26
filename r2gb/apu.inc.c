/* radare2 - LGPL - Copyright 2026 - pancake */

#define GB_AUDIO_RATE 44100
#define GB_AUDIO_BUFFER 0x30000
#define GB_AUDIO_SIZE 32768

typedef struct {
	bool enabled;
	bool dac;
	bool envelope_running;
	ut16 length;
	ut32 timer;
	ut8 position;
	ut8 volume;
	ut8 envelope_timer;
} GameBoySoundChannel;

typedef struct {
	ut8 registers[0x30];
	GameBoySoundChannel channel[4];
	bool powered;
	bool sweep_enabled;
	bool sweep_negated;
	ut8 sweep_timer;
	ut16 sweep_shadow;
	ut16 lfsr;
	ut8 frame_step;
	ut8 wave_sample;
	ut32 sample_clock;
	st32 capacitor[2];
} GameBoyAPU;

static ut16 gameboy_apu_frequency(GameBoyAPU *apu, int channel) {
	int base = channel * 5;
	return apu->registers[base + 3] | ((apu->registers[base + 4] & 7) << 8);
}

static ut32 gameboy_apu_period(GameBoyAPU *apu, int channel) {
	if (channel == 3) {
		ut8 polynomial = apu->registers[0x12];
		ut32 divisor = (polynomial & 7)? (polynomial & 7) * 16: 8;
		return divisor << (polynomial >> 4);
	}
	return (2048 - gameboy_apu_frequency (apu, channel)) * (channel == 2? 2: 4);
}

static ut16 gameboy_apu_sweep(GameBoyAPU *apu) {
	ut8 sweep = apu->registers[0];
	ut16 change = apu->sweep_shadow >> (sweep & 7);
	if (sweep & 8) {
		apu->sweep_negated = true;
		return apu->sweep_shadow - change;
	}
	ut16 frequency = apu->sweep_shadow + change;
	if (frequency > 2047) {
		apu->channel[0].enabled = false;
	}
	return frequency;
}

static void gameboy_apu_frame(GameBoyAPU *apu) {
	if (!apu->powered) {
		return;
	}
	int i;
	if (!(apu->frame_step & 1)) {
		for (i = 0; i < 4; i++) {
			GameBoySoundChannel *channel = &apu->channel[i];
			if ((apu->registers[i * 5 + 4] & 0x40) && channel->length && !--channel->length) {
				channel->enabled = false;
			}
		}
	}
	if (apu->frame_step == 2 || apu->frame_step == 6) {
		if (apu->sweep_timer && !--apu->sweep_timer) {
			ut8 sweep = apu->registers[0];
			apu->sweep_timer = (sweep >> 4) & 7;
			if (!apu->sweep_timer) {
				apu->sweep_timer = 8;
			}
			if (apu->sweep_enabled && (sweep & 0x70)) {
				ut16 frequency = gameboy_apu_sweep (apu);
				if (frequency < 2048 && (sweep & 7)) {
					apu->sweep_shadow = frequency;
					apu->registers[3] = frequency;
					apu->registers[4] = (apu->registers[4] & 0xf8) | (frequency >> 8);
					gameboy_apu_sweep (apu);
				}
			}
		}
	}
	if (apu->frame_step == 7) {
		for (i = 0; i < 4; i++) {
			GameBoySoundChannel *channel = &apu->channel[i];
			ut8 envelope = apu->registers[i * 5 + 2];
			if (i == 2 || !channel->envelope_running || !channel->envelope_timer || --channel->envelope_timer) {
				continue;
			}
			channel->envelope_timer = (envelope & 7)? envelope & 7: 8;
			if (envelope & 7) {
				int volume = channel->volume + ((envelope & 8)? 1: -1);
				if (volume >= 0 && volume <= 15) {
					channel->volume = volume;
				} else {
					channel->envelope_running = false;
				}
			}
		}
	}
	apu->frame_step = (apu->frame_step + 1) & 7;
}

static ut8 gameboy_apu_read(GameBoyAPU *apu, ut16 address) {
	static const ut8 masks[0x20] = {
		0x80, 0x3f, 0, 0xff, 0xbf, 0xff, 0x3f, 0, 0xff, 0xbf,
		0x7f, 0xff, 0x9f, 0xff, 0xbf, 0xff, 0xff, 0, 0, 0xbf,
		0, 0, 0x70, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};
	if (address == 0xff26) {
		ut8 status = (apu->powered? 0x80: 0) | 0x70;
		int i;
		for (i = 0; i < 4; i++) {
			status |= apu->channel[i].enabled << i;
		}
		return status;
	}
	int index = address - 0xff10;
	return apu->registers[index] | (index < 0x20? masks[index]: 0);
}

static void gameboy_apu_write(GameBoyAPU *apu, ut16 address, ut8 value) {
	int index = address - 0xff10;
	if (index >= 0x20) {
		apu->registers[index] = value;
		return;
	}
	if (address == 0xff26) {
		bool powered = value & 0x80;
		if (apu->powered && !powered) {
			memset (apu->registers, 0, 0x20);
			int i;
			for (i = 0; i < 4; i++) {
				ut16 length = apu->channel[i].length;
				memset (&apu->channel[i], 0, sizeof (apu->channel[i]));
				apu->channel[i].length = length;
			}
		}
		if (!apu->powered && powered) {
			apu->frame_step = 0;
			apu->wave_sample = 0;
		}
		apu->powered = powered;
		return;
	}
	if (index >= 0x17 || index == 5 || index == 0xf) {
		return;
	}
	if (index < 0x14) {
		int number = index / 5;
		int reg = index % 5;
		GameBoySoundChannel *channel = &apu->channel[number];
		if (reg == 1) {
			channel->length = (number == 2)? 256 - value: 64 - (value & 0x3f);
		}
		if (!apu->powered) {
			return;
		}
		ut8 old = apu->registers[index];
		apu->registers[index] = value;
		if (index == 0 && apu->sweep_negated && (old & 8) && !(value & 8)) {
			apu->channel[0].enabled = false;
		}
		if ((number == 2 && reg == 0) || (number != 2 && reg == 2)) {
			channel->dac = value & (number == 2? 0x80: 0xf8);
			if (!channel->dac) {
				channel->enabled = false;
			}
		}
		if (reg == 4) {
			bool extra_length = (apu->frame_step & 1) && !(old & 0x40) && (value & 0x40);
			if (extra_length && channel->length && !--channel->length) {
				channel->enabled = false;
			}
			if (value & 0x80) {
				channel->enabled = channel->dac;
				if (!channel->length) {
					channel->length = number == 2? 256: 64;
					if ((apu->frame_step & 1) && (value & 0x40)) {
						channel->length--;
					}
				}
				channel->timer = gameboy_apu_period (apu, number);
				ut8 envelope = apu->registers[number * 5 + 2];
				channel->volume = envelope >> 4;
				channel->envelope_timer = (envelope & 7)? envelope & 7: 8;
				channel->envelope_running = true;
				if (number == 0) {
					apu->sweep_shadow = gameboy_apu_frequency (apu, 0);
					apu->sweep_timer = (apu->registers[0] >> 4) & 7;
					if (!apu->sweep_timer) {
						apu->sweep_timer = 8;
					}
					apu->sweep_enabled = apu->registers[0] & 0x77;
					apu->sweep_negated = false;
					if (apu->registers[0] & 7) {
						gameboy_apu_sweep (apu);
					}
				} else if (number == 2) {
					channel->position = 0;
				} else if (number == 3) {
					apu->lfsr = 0x7fff;
				}
			}
		}
	} else if (apu->powered) {
		apu->registers[index] = value;
	}
}

static bool gameboy_apu_tick(GameBoyAPU *apu, ut8 sample[4]) {
	static const ut8 duty[] = { 0x80, 0x81, 0xe1, 0x7e };
	int i;
	if (apu->powered) {
		for (i = 0; i < 4; i++) {
			GameBoySoundChannel *channel = &apu->channel[i];
			if (!channel->enabled || (channel->timer && --channel->timer)) {
				continue;
			}
			channel->timer = gameboy_apu_period (apu, i);
			channel->position = (channel->position + 1) & (i == 2? 31: 7);
			if (i == 2) {
				ut8 wave = apu->registers[0x20 + channel->position / 2];
				apu->wave_sample = (wave >> ((channel->position & 1)? 0: 4)) & 15;
			} else if (i == 3) {
				ut16 feedback = (apu->lfsr ^ (apu->lfsr >> 1)) & 1;
				apu->lfsr = (apu->lfsr >> 1) | (feedback << 14);
				if (apu->registers[0x12] & 8) {
					apu->lfsr = (apu->lfsr & ~0x40) | (feedback << 6);
				}
			}
		}
	}
	apu->sample_clock += GB_AUDIO_RATE;
	if (apu->sample_clock < 4194304) {
		return false;
	}
	apu->sample_clock -= 4194304;
	int left = 0, right = 0;
	for (i = 0; i < 4; i++) {
		GameBoySoundChannel *channel = &apu->channel[i];
		if (!apu->powered || !channel->dac) {
			continue;
		}
		int output = 0;
		if (channel->enabled) {
			if (i < 2) {
				output = (duty[apu->registers[i * 5 + 1] >> 6] & (1 << channel->position))? channel->volume: 0;
			} else if (i == 2) {
				ut8 level = (apu->registers[0xc] >> 5) & 3;
				output = level? apu->wave_sample >> (level - 1): 0;
			} else {
				output = (apu->lfsr & 1)? 0: channel->volume;
			}
		}
		int analog = 15 - output * 2;
		if (apu->registers[0x15] & (1 << i)) {
			right += analog;
		}
		if (apu->registers[0x15] & (0x10 << i)) {
			left += analog;
		}
	}
	int mixed[2] = {
		left * (((apu->registers[0x14] >> 4) & 7) + 1) * 64,
		right * ((apu->registers[0x14] & 7) + 1) * 64
	};
	for (i = 0; i < 2; i++) {
		st32 filtered = mixed[i] - apu->capacitor[i];
		apu->capacitor[i] = mixed[i] - (filtered * 255 / 256);
		r_write_le16 (sample + i * 2, R_CLAMP (filtered, ST16_MIN, ST16_MAX));
	}
	return true;
}
