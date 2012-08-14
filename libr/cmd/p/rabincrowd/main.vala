/* bincrowd vala - radare example */
using Bincrowd;
using Radare;

const string SERVER = "http://bincrowd.zynamics.com/RPC2/";

string username = null;
string password = null;
const OptionEntry[] options = {
	{ "user", 'u', 0, OptionArg.STRING, ref username, "Set user name" },
	{ "pass", 'p', 0, OptionArg.STRING, ref password, "Password" },
	{ null }
};

void main(string[] args) {
	try {
		var oc = new OptionContext ("rabincrowd");
		oc.set_help_enabled (true);
		oc.add_main_entries (options, null);
		oc.parse (ref args);
	} catch (OptionError e) {
		stderr.printf ("Try -h\n");
		return;
	}
	if (username == null || password == null) {
		stderr.printf ("Try -u user -p pass\n");
		return;
	}

	var bc = new BinCrowd ("pancake", "123");
	if (bc.connect (SERVER)) {
		print ("Connected.\n");
		RCore core = new RCore ();
		core.file_open ("/bin/ls", 0);
		var target = new RadareTarget (core);
		bc.upload (target);
	} else {
		stderr.printf ("Error: %s\n", bc.message);
	}
	print ("Prime: %d\n", Bincrowd.primes[3]);
}
