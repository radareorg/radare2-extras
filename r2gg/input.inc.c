/* radare2 - LGPL - Copyright 2026 - pancake */

typedef struct {
	ut64 release[8];
	ut64 hold_us;
	ut8 held;
	ut8 escape;
	ut8 sequence_length;
	char sequence[64];
	bool event_types;
} GameGearInput;

static ut8 gamegear_visual_key(int key) {
	switch (key) {
	case 'h': return 2;
	case 'j': return 8;
	case 'k': return 4;
	case 'l': return 1;
	case 'a': return 16;
	case 's': return 32;
	case 'f':
	case 'F': return 128;
	}
	return 0;
}

static bool gamegear_input_event(GameGearInput *input, ut32 key, ut32 modifiers, ut32 event, bool enhanced) {
	if (event != 3 && (key == 'q' || key == 3 || key == 4 || ((modifiers & 4) && (key == 'c' || key == 'd')))) {
		return false;
	}
	ut8 mask = gamegear_visual_key (key);
	ut64 now = r_time_now_mono ();
	int bit;
	for (bit = 0; bit < 8; bit++) {
		if (!(mask & (1 << bit))) {
			continue;
		}
		if (enhanced) {
			input->release[bit] = 0;
			if (event == 3) {
				input->held &= ~mask;
			} else {
				input->held |= mask;
			}
		} else {
			input->release[bit] = now + input->hold_us;
		}
	}
	return true;
}

static bool gamegear_input_sequence(GameGearInput *input, int final) {
	input->sequence[input->sequence_length] = 0;
	if (final != 'u') {
		if (final == 'O' && !input->sequence_length) {
			input->held = 0;
			memset (input->release, 0, sizeof (input->release));
		}
		return true;
	}
	char *cursor = input->sequence;
	char *end;
	if (*cursor == '?') {
		unsigned long flags = strtoul (cursor + 1, &end, 10);
		if (end != cursor + 1 && !*end) {
			input->event_types = (flags & 10) == 10;
		}
		return true;
	}
	unsigned long key = strtoul (cursor, &end, 10);
	if (end == cursor || key > 0x10ffff) {
		return true;
	}
	unsigned long modifiers = 1, event = 1;
	if (*end == ';') {
		cursor = end + 1;
		modifiers = strtoul (cursor, &end, 10);
		if (end == cursor || !modifiers || modifiers > 256) {
			return true;
		}
		if (*end == ':') {
			cursor = end + 1;
			event = strtoul (cursor, &end, 10);
			if (end == cursor || event < 1 || event > 3) {
				return true;
			}
		}
	}
	if (*end) {
		return true;
	}
	if (event != 1) {
		input->event_types = true;
	}
	return gamegear_input_event (input, key, modifiers - 1, event, input->event_types || event != 1);
}

static bool gamegear_input_byte(GameGearInput *input, int key) {
	if (key == 27) {
		input->escape = 1;
		input->sequence_length = 0;
		return true;
	}
	if (input->escape == 1) {
		input->escape = key == '['? 2: key == 'O'? 3: 0;
		return true;
	}
	if (input->escape == 3) {
		input->escape = 0;
		return true;
	}
	if (input->escape == 2) {
		if (key >= '@' && key <= '~') {
			input->escape = 0;
			return gamegear_input_sequence (input, key);
		}
		if (key < 0x20 || key > 0x3f || input->sequence_length >= sizeof (input->sequence) - 1) {
			input->escape = 0;
		} else {
			input->sequence[input->sequence_length++] = key;
		}
		return true;
	}
	return gamegear_input_event (input, key, 0, 1, false);
}

static bool gamegear_visual_input(RCoreGameGear *gg, GameGearInput *input) {
	RCons *cons = gg->core->cons;
	int i;
	for (i = 0; i < 128; i++) {
		int key = cons->input_state.readbuffer_length > 0? r_cons_readchar (cons): r_cons_readchar_timeout (cons, 0);
		r_cons_set_raw (cons, true);
		if (key < 0) {
			break;
		}
		if (!gamegear_input_byte (input, key)) {
			return false;
		}
	}
	ut8 keys = input->held;
	ut64 now = r_time_now_mono ();
	for (i = 0; i < 8; i++) {
		if (now < input->release[i]) {
			keys |= 1 << i;
		}
	}
	gamegear_keys (gg, keys);
	return true;
}
