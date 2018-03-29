#include <stdio.h>
#include "toxcore/tox.h"

typedef struct DHT_node {
	const char *ip;
	uint16_t port;
	const char key_hex[TOX_PUBLIC_KEY_SIZE*2 + 1]; // 1 for null terminator
	unsigned char key_bin[TOX_PUBLIC_KEY_SIZE];
} DHT_node;

static DHT_node nodes[] =
{
	{"130.133.110.14", 33445, "461FA3776EF0FA655F1A05477DF1B3B614F7D6B124F7DB1DD4FE3C08B03B640F", {0}},
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
	printf ("UDP %d\n", tox_self_get_udp_port(t, NULL));
	printf ("TDP %d\n", tox_self_get_tcp_port(t, NULL));
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
			addfriend(tox);
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
	tox_self_get_address(t, self);
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
	printf ("FREIDN CAME\n");
	/*
	   printf ("Friend request %s\n", message);
	   tox_friend_add_norequest(tox, public_key, &err_friend_add);
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
	printf ("GOT MSG %d %s\n", type, message);
//	tox_self_set_typing(tox, friend_number, true, NULL);
	tox_friend_send_message (tox, friend_number, type, message, length,
			&err_send);
	if (err_send != TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
		fprintf(stderr, "unable to send message back to friend %d: %d\n",
				friend_number, err_send);
	}
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
	printf ("read receipt %d\n", friend_number);
}

uint8_t data[4096] = {0};

int main() {
	Tox *t = NULL;
	struct Tox_Options *options = tox_options_new(NULL);
	FILE *fd = fopen("tox.data", "rb");
	if (fd) {
		printf("Using tox.data\n");
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
		printf("cannot new\n");
		return 1;
	}
		int sz = tox_get_savedata_size (t);
		uint8_t *buf = (uint8_t *)calloc (sz, 1);
		tox_get_savedata (t, buf);
		printf ("Savedata %d\n", sz);
		FILE *fd = fopen("tox.data", "w");
		fwrite(buf, sz, 1, fd);
		fclose(fd);
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

	// tox_friend_send_message(t, 0, TOX_MESSAGE_TYPE type, const uint8_t *message, size_t length, TOX_ERR_FRIEND_SEND_MESSAGE *error);
	// bool tox_self_set_typing(Tox *tox, uint32_t friend_number, bool typing, TOX_ERR_SET_TYPING *error);
	printf ("Connecting...\n");
	while (true) {
		usleep (1000 * tox_iteration_interval (t));
		tox_iterate (t, NULL);
	}
	tox_kill (t);

	return 0;
}
