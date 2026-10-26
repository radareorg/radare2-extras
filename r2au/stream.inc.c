#define AU_QUEUE_SIZE 32768

static ut32 audio_queue_users;

typedef struct {
	ao_device *device;
	RThread *thread;
	RThreadLock *lock;
	RThreadCond *ready;
	ut8 samples[AU_QUEUE_SIZE];
	ut32 read;
	ut32 length;
	ut32 frame_size;
	bool stopping;
	bool failed;
} AudioQueue;

static RThreadFunctionRet audio_queue_worker(RThread *thread) {
	AudioQueue *queue = thread->user;
	ut8 samples[2048];
	r_th_lock_enter (queue->lock);
	while (!queue->length && !queue->stopping) {
		r_th_cond_wait (queue->ready, queue->lock, 0);
	}
	if (queue->stopping) {
		r_th_lock_leave (queue->lock);
		return R_TH_STOP;
	}
	ut32 length = R_MIN (queue->length, sizeof (samples));
	length -= length % queue->frame_size;
	ut32 first = R_MIN (length, AU_QUEUE_SIZE - queue->read);
	memcpy (samples, queue->samples + queue->read, first);
	memcpy (samples + first, queue->samples, length - first);
	queue->read = (queue->read + length) % AU_QUEUE_SIZE;
	queue->length -= length;
	r_th_lock_leave (queue->lock);
	if (!ao_play (queue->device, (char *)samples, length)) {
		r_th_lock_enter (queue->lock);
		queue->failed = true;
		r_th_lock_leave (queue->lock);
		return R_TH_STOP;
	}
	return R_TH_REPEAT;
}

static void audio_queue_free(AudioQueue *queue) {
	if (!queue) {
		return;
	}
	if (queue->thread) {
		r_th_lock_enter (queue->lock);
		queue->stopping = true;
		r_th_cond_signal (queue->ready);
		r_th_lock_leave (queue->lock);
		r_th_wait (queue->thread);
		r_th_free (queue->thread);
	}
	r_th_cond_free (queue->ready);
	r_th_lock_free (queue->lock);
	if (queue->device) {
		ao_close (queue->device);
	}
	free (queue);
}

static bool audio_queue_command(RCorePluginSession *session, RCons *cons, const char *input) {
	RCore *core = session->core;
	core->num->value = 0;
	if (!strcmp (input, "auq?")) {
		r_cons_println (cons,
			"auqi [rate bits channels [driver]] initialize asynchronous PCM playback (default 44100 16 2)\n"
			"auq address length        enqueue signed little-endian PCM; $? = bytes accepted\n"
			"auqs                      queued bytes; $? = bytes, or -1 on playback failure\n"
			"auq-                      stop playback and release the device");
		core->num->value = 1;
	} else if (!strcmp (input, "auq-")) {
		audio_queue_free (session->data);
		session->data = NULL;
		core->num->value = 1;
	} else if (!strcmp (input, "auqi") || r_str_startswith (input, "auqi ")) {
		int rate = 44100, bits = 16, channels = 2;
		char driver[32] = {0};
		int arguments = input[4]? sscanf (input + 5, "%d %d %d %31s", &rate, &bits, &channels, driver): 3;
		if (arguments < 3) {
			R_LOG_ERROR ("Usage: auqi [rate bits channels [driver]]");
			return true;
		}
		if (rate < 8000 || rate > 192000 || bits != 16 || channels < 1 || channels > 2) {
			R_LOG_ERROR ("Expected 8000..192000 Hz, 16 bits, and 1 or 2 channels");
			return true;
		}
		audio_queue_free (session->data);
		session->data = NULL;
		AudioQueue *queue = R_NEW0 (AudioQueue);
		ao_sample_format format = { .bits = bits, .rate = rate, .channels = channels, .byte_format = AO_FMT_LITTLE };
		int driver_id = *driver? ao_driver_id (driver): ao_default_driver_id ();
		queue->device = ao_open_live (driver_id, &format, NULL);
		if (!queue->device) {
			R_LOG_ERROR ("Cannot open audio output device");
			audio_queue_free (queue);
			return true;
		}
		queue->frame_size = channels * 2;
		queue->lock = r_th_lock_new (false);
		queue->ready = r_th_cond_new ();
		if (!queue->lock || !queue->ready || !(queue->thread = r_th_new (audio_queue_worker, queue, 0))) {
			audio_queue_free (queue);
			return true;
		}
		r_th_start (queue->thread);
		session->data = queue;
		core->num->value = 1;
	} else if (!strcmp (input, "auqs")) {
		AudioQueue *queue = session->data;
		if (queue) {
			r_th_lock_enter (queue->lock);
			core->num->value = queue->failed? UT64_MAX: queue->length;
			r_th_lock_leave (queue->lock);
			r_cons_printf (cons, "%"PFMT64d"\n", core->num->value);
		}
	} else if (r_str_startswith (input, "auq ")) {
		AudioQueue *queue = session->data;
		const char *length_arg = strchr (input + 4, ' ');
		if (!queue || !length_arg) {
			R_LOG_ERROR ("Initialize with auqi, then auq address length");
			return true;
		}
		char *address_arg = r_str_ndup (input + 4, length_arg - input - 4);
		ut64 address = r_num_math (core->num, address_arg);
		free (address_arg);
		ut64 length = r_num_math (core->num, length_arg + 1);
		core->num->value = 0;
		if (!length || length > AU_QUEUE_SIZE || length % queue->frame_size) {
			R_LOG_ERROR ("PCM length must contain whole sample frames and fit in %d bytes", AU_QUEUE_SIZE);
			return true;
		}
		ut8 *samples = malloc (length);
		if (!samples) {
			return true;
		}
		if (r_io_read_at (core->io, address, samples, length)) {
			r_th_lock_enter (queue->lock);
			if (!queue->failed && length <= AU_QUEUE_SIZE - queue->length) {
				ut32 write = (queue->read + queue->length) % AU_QUEUE_SIZE;
				ut32 first = R_MIN (length, AU_QUEUE_SIZE - write);
				memcpy (queue->samples + write, samples, first);
				memcpy (queue->samples, samples + first, length - first);
				queue->length += length;
				core->num->value = length;
				r_th_cond_signal (queue->ready);
			}
			r_th_lock_leave (queue->lock);
		}
		free (samples);
	} else {
		R_LOG_ERROR ("Unknown audio queue command (auq?)");
	}
	return true;
}

static bool audio_queue_init(RCorePluginSession *session) {
	if (!audio_queue_users++) {
		ao_initialize ();
	}
	return true;
}

static bool audio_queue_fini(RCorePluginSession *session) {
	audio_queue_free (session->data);
	session->data = NULL;
	if (!--audio_queue_users) {
		if (device) {
			au_fini ();
		}
		ao_shutdown ();
	}
	return true;
}

static RCmdResult audio_queue_call(RCmdContext *context) {
	RCorePluginSession *session = context->handler_user;
	char *input = r_str_newf ("auq%s", context->subcmd.a);
	audio_queue_command (session, context->cons, input);
	free (input);
	return (RCmdResult) { .has_value = true, .value = session->core->num->value };
}
