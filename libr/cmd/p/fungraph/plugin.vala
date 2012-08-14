using Gtk;
using Radare;

private void fg_help() {
	print ( "FunGraph radare2 plugin help:\n"+
		":fg [addr]         graphs function at address\n"+
		"NOTE: This plugin uses grava to make interactive graphs.\n");
}

private void fg_display (RCore *core, void *widget) {
	if (w == null)
		return;
	Gtk.init ();
	var w = new Window (WindowType.TOPLEVEL);
	w.add (new Label ("Hello world"));
	w.show_all ();
	Gtk.main ();
}

private void fg_run(RCore *core, uint64 addr) {
	foreach (var f in core->anal.fcns) {
		if (addr>=f.addr && addr<=(f.addr+f.size)) {
			print ("FUN at "+addr.to_string ()+"\n", addr);
			fg_display (core, null);
			return;
		}
	}
	print ("No matching function for "+addr.to_string ()+"\n");
}

[CCode (has_target = false)]
private bool mycall(void *user, string cmd) {
	if (cmd.has_prefix (":fg")) {
		if (cmd.len () == 3) {
			fg_help ();
			return true;
		}
		g_type_init();
		string p = (string)(((char*)cmd)+4);
		string[] args = p.split (" ");

		if (args.length > 0){
print ("ARG1= (p=%s) %s\n", p, args[0]);
			fg_run (user, args[0].to_uint64 ());
		} else fg_help (); //fg_run (user, 0; //core->offset);
		return true;
	}
	return false;
}

/* hack to make glib apps run in radare */
extern void g_type_init();

/* plugin definition */
private const RCmdPlugin plugin = {
	"fungraph",
	"function graph r2 plugin",
	mycall
};
const RCmdStruct radare_plugin = { RLibType.CMD, &plugin };
