#define KDP_DEFAULT_PORT 41139


#include <stdio.h>
#include <stdlib.h>

#include "event-top.c"
#include "event-loop.c"
int quit_flag = 0;
int inferior_pid = -1;
int sync_execution = 1;
int target_executing = 1;
#include "defs.h"
#include "target.c"

#include "kdp-udp.c"
#include "kdp-transactions.c"
#include "kdp-protocol.c"
#include "remote-kdp.c"


static int kdp_demo(char *arg) {
	kdp_attach (arg, 1);

	// read memory
	// read regs
	char data[32];
	kdp_xfer_memory (0xffffff80006343b9, data, 4, 0);
	printf ("%02x %02x %02x %02x\n",
		data[0], data[1], data[2], data[3]);

	kdp_detach (arg, 1);
	return 0;
}

int main(int argc, char **argv) {
	if (argc<2) {
		eprintf ("Missing IP\n");
		return 1;
	}
	return kdp_demo (argv[1]);
}
