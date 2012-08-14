using Bincrowd;
using Radare;

public class RadareTarget : Bincrowd.Target {
	uint64 addr;
	RCore *core;

	public RadareTarget (RCore core, uint64 addr = uint64.MAX) {
		this.addr = addr;
		this.core = core;
		this.target = core.file.filename;
		reset ();
		update ();
	}

	public void reset () {
		this.md5 = ""; // XXX
		this.ostype = get_os_type ();
		this.language = "C"; // XXX
	}

	public void update() {
		this.functions = bc_get_functions (addr);
		this.md5 = core->config.get ("file.md5");
		if (this.md5 == null || this.md5.len ()==0) 
			this.md5 = "unknown";
		this.description = ""; // file.desc
		this.name = core->config.get ("file.path");
		this.processor = get_arch();
		this.language = "Visual C++";
	}

	private string get_arch() {
		switch (core->config.get ("asm.arch")) {
		case "x86":
			return "metapc";
		default:
			stderr.printf ("Unsupported asm.arch\n");
			break;
		}
		return "metapc";
	}

	private int get_os_type() {
		// from ostype_t @ pro.h
		switch (core->config.get ("asm.os")) {
		case "dos":
			return 0;
		case "aix":
			return 1;
		case "os2":
			return 2;
		case "windows":
			return 3;
		case "linux":
			return 4;
		case "osx":
			return 5;
		case "bsd":
			return 7;
		}
		print ("Unknown OS in asm.os\n");
		return 0; // unknown
	}

	private string filter_opcode(string op) {
		switch (op) {
		case "ret":
			return "retn";
		}
		return op;
	}

	private List<Bincrowd.Function> bc_get_functions(uint64 addr) {
		var funs = new List <Bincrowd.Function> ();
		print ("This is teh result: 0x%08llx\n", core->num.math ("eip+32"));
		foreach (var f in core->anal.fcns) {
			if (addr==uint64.MAX || addr==f.addr) {
				var fun = new Bincrowd.Function();

				/* arguments and  variables */
				foreach (var v in f.vars) {
					var foo = new Variable();
					foo.name = v.name;
					switch (v.type) {
					case RAnal.VarType.ARG:
					case RAnal.VarType.ARGREG:
						fun.args.append (foo);
						break;
					case RAnal.VarType.LOCAL:
						fun.vars.append (foo);
						break;
					}
				}
				fun.name = f.name;
				fun.base_address = core->io.va;
				fun.rva = f.addr;
				print ("fun %s @ 0x%08llx\n", f.name, f.addr);
				Bincrowd.Node? root = null;
				var bbs = core->anal.fcn_bb_list (f);
				foreach (var b in bbs) {
					print (" BB: "+ut64fmt+" ("+ut64fmtd+")\n",
						b.addr, b.size);
					int calls = 0;
					var opstr = "";
					for (uint64 a = b.addr; a<(b.addr+b.size); ) {
						var opcode = core->op_str (a);
						var opdata = core->op_anal (a);
						opstr += filter_opcode (opcode.split (" ")[0]);
						switch (opdata.type) {
						case RAnal.OpType.RCALL:
						case RAnal.OpType.CALL:
							calls++;
							break;
						}
						a += opdata.length;
					}
					print ("   - bsize: "+ut64fmtd+"\n", b.size);
					print ("   - opstr: %s\n", opstr);
					print ("   - prime: %d\n", BinCrowd.get_prime (opstr));
					print ("   - calls: %d\n", calls);

					int nedges = 0;
					if (b.jump != uint64.MAX) nedges++;
					if (b.fail != uint64.MAX) nedges++;
					print ("   - edges: %u\n", nedges); //fun.edges.length ());

					var node = new Bincrowd.Node (b.addr, b.size, calls,
						BinCrowd.get_prime (opstr));
					node.jump = b.jump;
					node.fail = b.fail;
					//TODO: fun.edges.append (new Edge (node, node2));
					// node.foo = bar
					if (b.type==RAnal.BlockType.HEAD)
						if (root != node)
							root = node;
						else warning ("Wrong code analysis..dupped HEAD blocks");
					fun.nodes.append (node);
				}
				if (addr != uint64.MAX)
					break;

				fun.update ();

				print ("Function edges: %u\n", fun.edges.length ());
				// testing rcmds
				//core->cmd ("pd 4 @ 0x%08llx".printf (f.addr), false);
				//core->cmd ("x", false);
				fun.update();
				print ("Function prime: "+ut64fmtd+"\n", fun.prime);
				if (fun.edges.length ()>0) {
					funs.append (fun);
				} else print ("IGNORED\n");
			}
		}
		return funs;
	}
}
