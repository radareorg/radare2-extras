/* radare2 - LGPL - Copyright 2026 - pancake */

typedef struct {
	ut64 release[8];
	ut64 hold_us;
	ut32 quit_key;
	ut8 held;
	ut8 escape;
	ut8 sequence_length;
	char sequence[64];
	bool event_types, toggle_mute;
} TamaInput;

static ut8 tama_visual_key(int key) {
	switch (key) {
	case 'a': return 1;
	case 's': return 2;
	case 'd': return 4;
	}
	return 0;
}

static bool tama_input_event(TamaInput *input, ut32 key, ut32 modifiers, ut32 event, bool enhanced) {
	if (event == 3 && input->quit_key == key) {
		return false;
	}
	if (event != 3 && (key == 'q' || key == 3 || key == 4 || ((modifiers & 4) && (key == 'c' || key == 'd')))) {
		if (enhanced) {
			// Consume the matching release before returning to r2's line editor.
			input->quit_key = key;
			return true;
		}
		return false;
	}
	if ((key == 'm' || key == 'M') && event == 1 && !(modifiers & (2 | 4 | 8))) {
		input->toggle_mute = !input->toggle_mute;
	}
	ut8 mask = tama_visual_key (key);
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

static bool tama_input_sequence(TamaInput *input, int final) {
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
			input->event_types = (flags & 2) != 0;
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
	return tama_input_event (input, key, modifiers - 1, event, input->event_types || event != 1);
}

static bool tama_input_byte(TamaInput *input, int key) {
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
			return tama_input_sequence (input, key);
		}
		if (key < 0x20 || key > 0x3f || input->sequence_length >= sizeof (input->sequence) - 1) {
			input->escape = 0;
		} else {
			input->sequence[input->sequence_length++] = key;
		}
		return true;
	}
	return tama_input_event (input, key, 0, 1, input->event_types);
}

static bool tama_visual_input(RCoreTama *gg, TamaInput *input) {
	RCons *cons = gg->core->cons;
	int i;
	for (i = 0; i < 128; i++) {
		int key = cons->input_state.readbuffer_length > 0? r_cons_readchar (cons): r_cons_readchar_timeout (cons, 0);
		r_cons_set_raw (cons, true);
		if (key < 0) {
			break;
		}
		if (!tama_input_byte (input, key)) {
			return false;
		}
	}
	if (input->toggle_mute) {
		tama_audio_mute (gg, !gg->muted);
		input->toggle_mute = false;
	}
	ut8 keys = input->held;
	ut64 now = r_time_now_mono ();
	for (i = 0; i < 8; i++) {
		if (now < input->release[i]) {
			keys |= 1 << i;
		}
	}
	tama_keys (gg, keys);
	return true;
}
