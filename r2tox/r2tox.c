#include <stdio.h>
#include <r_core.h>
#include "toxcore/tox.h"

typedef struct DHT_node {
	const char *ip;
	uint16_t port;
	const char key_hex[TOX_PUBLIC_KEY_SIZE*2 + 1]; // 1 for null terminator
	unsigned char key_bin[TOX_PUBLIC_KEY_SIZE];
} DHT_node;

RThread *thread = NULL;
RCore *core = NULL;

static DHT_node nodes[] = {
	{"130.133.110.14",  33445, "461FA3776EF0FA655F1A05477DF1B3B614F7D6B124F7DB1DD4FE3C08B03B640F", {0}},
	   {"144.76.60.215",   33445, "04119E835DF3E78BACF0F84235B300546AF8B936F035185E2A8E9E0A67C8924F", {0}},
	   {"23.226.230.47",   33445, "A09162D68618E742FFBCA1C2C70385E6679604B2D80EA6E84AD0996A1AC8A074", {0}},
	   {"178.21.112.187",  33445, "4B2C19E924972CB9B57732FB172F8A8604DE13EEDA2A6234E348983344B23057", {0}},
	   {"195.154.119.113", 33445, "E398A69646B8CEACA9F0B84F553726C1C49270558C57DF5F3C368F05A7D71354", {0}},
	   {"192.210.149.121", 33445, "F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67", {0}}
};

static void addfriend(Tox *t) {
	const char *himsg = "hihihi";
	// 4A06ABE7C9846F227A173B788802B4E5FEE3A0BAE1D5F449FF50C09089C88B20676C0EB625F8
	const uint8_t friend_address[38] = {
		0x4a, 0x06, 0xab, 0xe7, 0xc9, 0x84, 0x6f, 0x22, 0x7a, 0x17,
		0x3b, 0x78, 0x88, 0x02, 0xb4, 0xe5, 0xfe, 0xe3, 0xa0, 0xba,
		0xe1, 0xd5, 0xf4, 0x49, 0xff, 0x50, 0xc0, 0x90, 0x89, 0xc8,
		0x8b, 0x20, 0x67, 0x6c, 0x0e, 0xb6, 0x25, 0xf8
	};

	TOX_ERR_FRIEND_ADD err;
	// int child = tox_friend_add (t, friend_address, himsg, strlen (himsg), &err);
	int child = tox_friend_add_norequest(t, friend_address, &err);
	printf ("SENDING HI TO %d\n", child);
	tox_friend_send_message(t, child, TOX_MESSAGE_TYPE_NORMAL, "hi", 2, &err);
	printf ("TOX ADD %d\n", err);
	printf ("FRIEND IS %d\n", child);
	// printf ("UDP %d\n", tox_self_get_udp_port(t, NULL));
	//printf ("TDP %d\n", tox_self_get_tcp_port(t, NULL));
}

static void self_connection_status_cb(Tox *tox, TOX_CONNECTION connection_status, void *user_data) {
	switch (connection_status) {
		case TOX_CONNECTION_NONE:
			printf("Offline\n");
			break;
		case TOX_CONNECTION_TCP:
			printf("Online, using TCP\n");
			break;
		case TOX_CONNECTION_UDP:
			printf("Online, using UDP\n");
			// addfriend(tox);
			break;
	}
}

static void print_tox_address(uint8_t *self) {
	size_t i;
	for (i = 0; i< TOX_ADDRESS_SIZE; i++) {
		printf ("%02x", self[i]);
	}
	printf("\n");
}

static void print_tox_my_address(Tox *t) {
	uint8_t self[TOX_ADDRESS_SIZE] = {0};
	tox_self_get_address (t, self);
	print_tox_address (&self);
}

static void handle_friend_name(Tox *tox, uint32_t friend_number, const uint8_t *name, size_t length, void *user_data) {
	printf ("NAME: %d %s\n", friend_number, name);
}

static void handle_friend_request(
		Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length,
		void *user_data) {
	// Accept the friend request:
	TOX_ERR_FRIEND_ADD err_friend_add;
	printf ("[tox] Friend request %s\n[tox] ", message);
	print_tox_address (public_key);
	int child = tox_friend_add_norequest (tox, public_key, &err_friend_add);
//	// int child = tox_friend_add (t, friend_address, himsg, strlen (himsg), &err);
//	int child = tox_friend_add_norequest(t, friend_address, &err);
//	char *himsg = "hi there";
//	int child = tox_friend_add (tox, public_key, himsg, strlen (himsg), &err_friend_add);
	printf ("child %d %d\n", child, err_friend_add);
/*
	if (err_friend_add != TOX_ERR_FRIEND_ADD_OK) {
		fprintf(stderr, "unable to add friend: %d\n", err_friend_add);
	}
*/
}

static void handle_friend_message(
		Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type,
		const uint8_t *message, size_t length,
		void *user_data) {
	TOX_ERR_FRIEND_SEND_MESSAGE err_send;
	eprintf ("<%d> %s\n", friend_number, message);
	if (*message != ':') {
		return;
	}
	tox_self_set_typing(tox, friend_number, true, NULL);
	char *cmd = r_str_ndup (message, length);
	char *res = r_core_cmd_str (core, cmd + 1);
	if (res && *res) {
		const int MAXK = 1280;
		int bak = 0;
		int k = 0;
		char *r = res;
		while (1) {
			if (strlen (r) > MAXK) {
				k = MAXK;
				bak = r[k];
				r[k] = 0;
				char *nl = r_str_rchr (r, NULL, '\n');
				if (nl) {
					r[k] = bak;
					bak = *nl;
					*nl = 0;
					k = nl - r; 
				}
			} else {
				bak = 0;
			}
			tox_friend_send_message (tox, friend_number, type, r, strlen (r), &err_send);
			// tox_friend_send_message (tox, friend_number, type, message, length, &err_send);
			if (err_send != TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
				fprintf(stderr, "unable to send message back to friend %d: %d\n",
						friend_number, err_send);
			}
			if (bak) {
				r[k] = bak;
				r += k;
			} else {
				break;
			}
		}
	} else {
		eprintf ("Invalid command?\n");
	}
	free (res);
	free (cmd);
	tox_self_set_typing(tox, friend_number, false, NULL);
}

static void handle_conference_title(Tox *tox, uint32_t conference_number, uint32_t peer_number, const uint8_t *title,
		size_t length, void *user_data) {
	printf ("TITLE %s\n", title);
}

static void handle_conference_message(Tox *tox, uint32_t conference_number, uint32_t peer_number,
		TOX_MESSAGE_TYPE type, const uint8_t *message, size_t length, void *user_data) {
	printf ("MSG #%d<%d> %s\n", conference_number, peer_number, message);
}

static void handle_conference_invite(Tox *tox, uint32_t friend_number, TOX_CONFERENCE_TYPE type, const uint8_t *cookie,
		size_t length, void *user_data) {
	printf ("GOT CHAN INVITE %s (%d)\n", cookie, length);
	TOX_ERR_CONFERENCE_JOIN err = 0;
	int chan = tox_conference_join(tox, friend_number, cookie, length, &err);
	printf ("Joined channel %d %d\n", chan, err);
}

static void handle_friend_lossy_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length, void *user_data) {
	printf ("lossy from %d\n", friend_number);
}

static void handle_friend_lossless_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length, void *user_data) {
	printf ("losslessy from %d\n", friend_number);
}

static void handle_friend_read_receipt(Tox *tox, uint32_t friend_number, uint32_t message_id, void *user_data) {
	// printf ("read receipt %d\n", friend_number);
}

static uint8_t data[4096] = {0};
static struct Tox *tox = NULL;

static void r2tox_save() {
	struct Tor *t = tox;
	int sz = tox_get_savedata_size (t);
	uint8_t *buf = (uint8_t *)calloc (sz, 1);
	tox_get_savedata (t, buf);
	printf ("Saving tox.data %d\n", sz);
	FILE *fd = fopen("tox.data", "w");
	fwrite(buf, sz, 1, fd);
	fclose(fd);
}

static int r2tox_mainloop(RThread *th, void *user) {
	while (!th->breaked) {
		usleep (1000 * tox_iteration_interval (tox));
		tox_iterate (tox, NULL);
	}
	return 0;
}
static void r2tox_iter() {
	size_t i = 10;
	while (i--) {
		usleep (1000 * tox_iteration_interval (tox));
		tox_iterate (tox, NULL);
	}
}

static int r2tox_connect() {
	if (tox) {
		printf ("Status: Online\n");
		print_tox_my_address (tox);
		return -1;
	}
	Tox *t = NULL;
	struct Tox_Options *options = tox_options_new(NULL);
	FILE *fd = fopen("tox.data", "rb");
	if (fd) {
		eprintf ("Using tox.data\n");
		size_t sz = fread (&data, 1, 4096, fd);
		fclose (fd);
		tox_options_set_savedata_length (options, sz);
		tox_options_set_savedata_type (options, TOX_SAVEDATA_TYPE_TOX_SAVE);
		tox_options_set_savedata_data (options, data, sz);
		t = tox_new (options, NULL);
		if (!t) {
			printf("cannot new\n");
			return 1;
		}
	} else {
		t = tox_new (NULL, NULL);
		if (!t) {
			eprintf ("cannot new\n");
			return 1;
		}
		// r2tox_save();
	}

	const char *username = "toxtest";
	const char *status = "Available";
	tox_self_set_name (t, username, strlen(username), NULL);
	tox_self_set_status_message (t, status, strlen(status), NULL);

	tox_callback_friend_name(t, handle_friend_name);
	tox_callback_friend_request (t, handle_friend_request);
	tox_callback_friend_message (t, handle_friend_message);
	tox_callback_friend_lossy_packet (t, handle_friend_lossy_packet);
	tox_callback_friend_lossless_packet (t, handle_friend_lossless_packet);
	tox_callback_friend_read_receipt (t, handle_friend_read_receipt);
	tox_callback_conference_invite(t, handle_conference_invite);
	tox_callback_conference_message(t, handle_conference_message);
	tox_callback_conference_title(t, handle_conference_title);

	// bootstrap
	size_t i;
	for (i = 0; i < sizeof(nodes)/sizeof(DHT_node); i ++) {
		sodium_hex2bin(nodes[i].key_bin, sizeof(nodes[i].key_bin),
				nodes[i].key_hex, sizeof(nodes[i].key_hex)-1, NULL, NULL, NULL);
		tox_bootstrap(t, nodes[i].ip, nodes[i].port, nodes[i].key_bin, NULL);
	}

	print_tox_my_address (t);
	tox_callback_self_connection_status (t, self_connection_status_cb);

	tox = t;
	// thread here
	if (!thread) {
		thread = r_th_new (r2tox_mainloop, NULL, 1);
		r_th_start (thread, true);
	}
	return 0;
}

static void r2tox_disconnect() {
	r_th_kill (thread, true);
	//r_th_free (thread);
	thread = NULL;
	tox_kill (tox);
	tox = NULL;
}

static void r2tox_addfriend(const char *addr) {
	if (!tox) {
		eprintf ("[tox] Not connected\n");
		return;
	}
	char *a = strdup (addr);
	if (!a) {
		return;
	}
	char *b = strchr (a, ' ');
	uint8_t fa[128] = {0};
	if (b) {
		*b++ = 0;
	}
b = NULL;
	int len = r_hex_str2bin (a, &fa);
	printf ("LEN %d (%s)\n", len, a);
// int friendid = tox_friend_add_norequest(tox, fa, NULL);
	int friendid = b
		? tox_friend_add (tox, fa, b, strlen(b), NULL)
		: tox_friend_add (tox, fa, "hi there", 8, NULL);
	printf ("friendid %d\n", friendid);
	free (a);
}

static void r2tox_msg(int friend, const char *msg) {
	(void)tox_friend_send_message (tox, friend, TOX_MESSAGE_TYPE_NORMAL, msg, strlen (msg), NULL);
}

static int _cmd_tox (RCore *core, const char *args) {
	switch (*args) {
		case '?':
			eprintf ("tox[?]       - expose current session to tox\n");
			eprintf ("tox          - start background thread connecting to tox\n");
			eprintf ("tox-         - disconnect from tox\n");
			eprintf ("toxc [f] [c] - send r2 command to friend id\n");
			eprintf ("toxf [key]   - add friend\n");
			eprintf ("toxf-[f]     - delete friend id\n");
			eprintf ("toxm [f] [m] - send message to friend id\n");
			eprintf ("toxn [name]  - change/set your name\n");
			eprintf ("toxs         - save current key and friends into tox.data\n");
			break;
		case 'f':
			if (args[1] == ' ') {
				r2tox_addfriend (args + 2);
			} else if (args[1] == '-') {
				tox_friend_delete (tox, atoi (args + 2), NULL);
			}
			break;
		case 'm':
			if (args[1] == ' ') {
				int friend = atoi (args + 2);
				char *msg = strchr (args + 3, ' ');
				if (msg) {
					r2tox_msg (friend, msg);
				}
			}
			break;
		case 'c':
			if (args[1] == ' ') {
				int friend = atoi (args + 2);
				char *msg = strchr (args + 3, ' ');
				if (msg) {
					*msg = ':';
					r2tox_msg (friend, msg);
					*msg = ' ';
				}
			}
			break;
		case 's':
			r2tox_save();
			break;
		case 'n':
			if (args[1] == ' ') {
				tox_self_set_name (tox, args + 2, strlen(args + 2), NULL);
			}
			break;
		case '-':
			r2tox_disconnect();
			break;
		case 0:
			r2tox_connect();
			break;
	}
}

static int r_cmd_tox(void *user, const char *input) {
	RCore *_core = (RCore *) user;
	if (!strncmp (input, "tox", 3)) {
		core = _core;
		_cmd_tox (core, input + 3);
		return true;
	}
	return false;
}

RCorePlugin r_core_plugin_r2tox = {
	.name = "r2tox",
	.desc = "expose current session to Tox",
	.license = "MIT",
	.call = r_cmd_tox,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_r2tox,
	.version = R2_VERSION
};
#endif

