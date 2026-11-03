/* radare2 - LGPL - Copyright 2026 - pancake */

static void tama_audio_flush(RCoreTama *gg) {
	if (!gg->audio_pending_size) {
		return;
	}
	ut32 offset = gg->audio_produced % TAMA_AUDIO_SIZE;
	ut32 first = R_MIN (gg->audio_pending_size, TAMA_AUDIO_SIZE - offset);
	r_io_fd_write_at (gg->io, gg->audio_fd, offset, gg->audio_pending, first);
	if (first < gg->audio_pending_size) {
		r_io_fd_write_at (gg->io, gg->audio_fd, 0, gg->audio_pending + first, gg->audio_pending_size - first);
	}
	gg->audio_produced += gg->audio_pending_size;
	gg->audio_pending_size = 0;
}

static void tama_audio_stop(RCoreTama *gg) {
	if (gg->audio_playing) {
		r_core_call (gg->core, "auq-");
		gg->audio_playing = false;
	}
}

static void tama_audio_mute(RCoreTama *tama, bool muted) {
	tama_audio_flush (tama);
	tama->muted = muted;
	tama->audio_consumed = tama->audio_produced;
	if (muted) {
		tama_audio_stop (tama);
	}
}

static bool tama_audio_start(RCoreTama *gg) {
	if (gg->muted) {
		return false;
	}
	if (gg->audio_playing) {
		return true;
	}
	RCore *core = gg->core;
	RListIter *iter;
	RCorePluginSession *session;
	bool available = false;
	r_list_foreach (core->rcmd->libstore->plugins, iter, session) {
		if (!strcmp (session->plugin->meta.name, "audio")) {
			available = true;
			break;
		}
	}
	if (!available) {
		R_LOG_WARN ("Audio needs the r2au plugin (r2pm -ci r2au)");
		return false;
	}
	core->num->value = 0;
	char *help = r_core_cmd_str (core, "auq?");
	bool streaming = help && strstr (help, "auqi ");
	free (help);
	if (!streaming) {
		R_LOG_WARN ("Update r2au for asynchronous PCM playback (auq?)");
		return false;
	}
	core->num->value = 0;
	r_core_call (core, "auqi 44100 16 2");
	gg->audio_playing = core->num->value == 1;
	return gg->audio_playing;
}

static bool tama_audio_submit(RCoreTama *gg, bool partial) {
	tama_audio_flush (gg);
	if (gg->audio_produced - gg->audio_consumed > TAMA_AUDIO_SIZE) {
		gg->audio_consumed = gg->audio_produced - TAMA_AUDIO_SIZE;
	}
	if (!partial && gg->audio_produced - gg->audio_consumed < 2048) {
		return true;
	}
	ut32 offset = gg->audio_consumed % TAMA_AUDIO_SIZE;
	ut32 length = R_MIN (gg->audio_produced - gg->audio_consumed, TAMA_AUDIO_SIZE - offset);
	length = R_MIN (length, 4096);
	if (!length) {
		return true;
	}
	char command[80];
	snprintf (command, sizeof (command), "auq 0x%x %u", TAMA_AUDIO_BUFFER + offset, length);
	r_core_call (gg->core, command);
	if (gg->core->num->value == length) {
		gg->audio_consumed += length;
		return true;
	}
	return false;
}
