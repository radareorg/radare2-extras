/* vala r2 bincrowd plugin */
using Radare;
using Bincrowd;

// TODO: move to r_util.vapi ??
const string ut64fmt = "0x%"+uint64.FORMAT_MODIFIER+"x";
const string ut64fmtd = "%"+uint64.FORMAT_MODIFIER+"d";

private string bc_user;
private string bc_pass;
private string bc_host;
private RCore* core;

private void bc_help() {
	print ( "BinCrowd radare2 plugin help:\n"+
		":bc auth [user] [pass]   define user and password\n"+
		":bc host [addr]          change bincrowd server address\n"+
		":bc pull [addr]          retrieve signatures from server\n"+
		":bc push [addr]          upload signatures to server\n"+
		"Default host is: "+BinCrowd.SERVER+"\n"+
		"See: http://bincrowd.zynamics.com/\n");
}

private BinCrowd? plug(uint64 addr) {
	if (bc_user == null || bc_pass == null) {
		print ("Usage: :bc auth [user] [pass]\n");
		return null;
	}
	var bc = new BinCrowd (bc_user, bc_pass);
	if (bc_host == null)
		bc_host = BinCrowd.SERVER;
	if (!bc.connect (bc_host)) {
		stderr.printf ("Cannot connect to host '%s'\n", bc_host);
		return null;
	}
	return bc;
}

private void bc_pull(uint64 addr) {
	var bc = plug (addr);
	if (bc != null)
		bc.download (new RadareTarget (core, addr));
}

private void bc_push(uint64 addr) {
	var bc = plug (addr);
	if (bc != null)
		bc.upload (new RadareTarget (core, addr));
}

[CCode (has_target = false)]
private bool mycall(void *user, string cmd) {
	if (cmd.has_prefix (":bc")) {
		if (cmd.len () == 3) {
			bc_help ();
			return true;
		}

		if (core == null) {
			core = (RCore*)user;
			g_type_init();
		}

		string p = (string)(((char*)cmd)+4);
		string[] args = p.split (" ");

		if (args.length > 0) {
			switch (args[0]) {
			case "auth":
				if (args.length>2) {
					bc_user = args[1];
					bc_pass = args[2];
				} else print ("Usage: :bc auth [user] [pass]\n");
				break;
			case "host":
				if (args.length>1) {
					bc_host = args[1];
				} else print ("Usage: :bc host [host]\n");
				break;
			case "push":
				if (args.length>1) {
					for (int i=1; i<args.length;i++)
						bc_push (core->num.math (args[i]));
				} else bc_push (uint64.MAX);
				break;
			case "pull":
				if (args.length>1) {
					for (int i=1; i<args.length;i++)
						bc_pull (core->num.math (args[i]));
				} else bc_pull (uint64.MAX);
				break;
			default:
				print (":bc: Invalid command. Try ':bc'\n");
				break;
			}
		} else bc_help ();
		return true;
	}
	return false;
}

/* hack to make glib apps run in radare */
extern void g_type_init();

/* plugin definition */
private const RCmdPlugin plugin = {
	"rabincrowd",
	"bincrowd r2 plugin (use :bc)",
	mycall
};
const RCmdStruct radare_plugin = { RLibType.CMD, &plugin };
