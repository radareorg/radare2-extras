/* bincrowd api for xmlrpc-vala and radare2 */
using XmlRpc;
using XmlRpc.Type;

const string NAME = "xmlrpc-vala";
const string VERSION = "1.0";
const string BC_VERSION= "1";

namespace Bincrowd {

public enum UploadReturn {
	SUCCESS = 0,
	COULDNT_READ_CONFIG_FILE = 1,
	COULDNT_CONNECT_TO_SERVER = 2,
	COULDNT_UPLOAD_DATA = 3,
	INCOMPLETE_DATA = 4,
	INVALID_VERSION_NUMBER = 5,
	USER_NOT_AUTHENTICATED = 6,
	FUNCTION_TOO_SMALL = 7,
	INTERNAL_ERROR = 8,
	NO_FUNCTION_AT_ADDRESS = 9,
	NO_FUNCTIONS_FOUND = 11
}

public enum DownloadReturn {
	SUCCESS = 0,
	COULDNT_READ_CONFIG_FILE = 1,
	COULDNT_RETRIEVE_DATA = 2,
	COULDNT_CONNECT_TO_SERVER = 3,
	INCOMPLETE_DATA = 4,
	INVALID_VERSION_NUMBER = 5,
	USER_NOT_AUTHENTICATED = 6,
	INTERNAL_ERROR = 7
}

public class BinCrowd {

	public static const string SERVER = "http://bincrowd.zynamics.com/RPC2/";
	/* private */
	private static Env env;
	private Client cli;
	private ServerInfo si;
	private XmlRpc.Value user;
	private XmlRpc.Value pass;
	private static bool initialized = false;

	/* public */
	public string message;

/*
	private static inline uint64 ipow(uint64 b, uint64 exp) {
		 uint64 result = 1;
		 while (exp!=0) {
			 if ((exp & 1)!=0)
				 result *= b;
			 exp >>= 1;
			 b *= b;
		 }
		 return result;
	}
*/

	public BinCrowd (string user, string pass) {
		if (!BinCrowd.initialized) {
			env = Env();
			Client.init (0, NAME, VERSION);
		}
		Client.create (env, 0, NAME, VERSION, null, 0, out cli);
		this.user = env.string_new (user);
		this.pass = env.string_new (pass);
	}

	public bool connect (string host) {
		si = new ServerInfo (env, host);
		if (env.fault_occurred) {
			message = env.fault_string;
			si = null;
		}
		return !env.fault_occurred;
	}

	public static uint64 prime_product(Bincrowd.Function fun) {
		uint64 prime = 1;

		foreach (var bb in fun.nodes) {
			//uint64 mod = ipow (2, 64);
			//if (mod != 0) prime = (prime * bb.prime) % mod;
			prime *= bb.prime;
		}
		return prime;
	}

	public static int get_prime(string mnemonic) {
		uint64 index = 0;
		var ch = (char *)mnemonic + mnemonic.length-1;
		do index = index*32 + (*ch-0x60) & 0xff;
		while (ch-- > (char*)mnemonic);
		return Bincrowd.primes[index % Bincrowd.primes.length];
	}

/*
	private uint64 calculate_node_prime(List<string> mnemonics) {
		uint64 ret = 0;
		foreach (var a in mnemonics) {
			// XXX return reduce(mul, map(get_prime, list_of_mnemonics), 1) % 2**64
			ret *= (get_prime (a)); // % ipow (2,64);
		}
		return ret;
	}
*/

	private XmlRpc.Value get_edges(Bincrowd.Function fun) {
		var ret = new XmlRpc.Array (env);
		foreach (var e in fun.edges) {
			var item = new XmlRpc.Struct (env);
			item.set_value (env, "indegree_source", env.int_new (e.indegree_source));
			item.set_value (env, "outdegree_source", env.int_new (e.outdegree_source));
			item.set_value (env, "indegree_target", env.int_new (e.indegree_target));
			item.set_value (env, "outdegree_target", env.int_new (e.outdegree_target));
			item.set_value (env, "topological_order_source", env.int_new (e.topological_order_source));
			item.set_value (env, "topological_order_target", env.int_new (e.topological_order_target));
			item.set_value (env, "source_prime", env.string_new (e.source.prime.to_string ()));
			item.set_value (env, "target_prime", env.string_new (e.target.prime.to_string ()));
			item.set_value (env, "target_call_num", env.int_new (e.target_call_num));
			item.set_value (env, "source_call_num", env.int_new (e.source_call_num));
			ret.append_item (env, item);
		}
		return ret;
	}

	public XmlRpc.Value get_function(Bincrowd.Target target, Bincrowd.Function fun, bool upload) {
		var ret = new XmlRpc.Struct (env);
		ret.set_value (env, "prime_product", env.string_new ("%d".printf (0)));

		ret.set_value (env, "edges", get_edges (fun));
		if (upload) {
			ret.set_value (env, "name", env.string_new (fun.name));
			ret.set_value (env, "description", env.string_new (fun.description));
			var funi = new XmlRpc.Struct (env);
				funi.set_value (env, "processor", env.string_new (target.processor));
				// BINCROWD BUG: base address cannot be bigger than 32 bits
				funi.set_value (env, "rva", env.int_new ((int)fun.rva));
				// BINCROWD BUG: base address cannot be bigger than 32 bits
				funi.set_value (env, "base_address", env.int_new ((int)fun.base_address));
				funi.set_value (env, "language", env.string_new (target.language));
				funi.set_value (env, "number_of_nodes", env.string_new (
					"%u".printf (fun.nodes.length ())));
			ret.set_value (env, "function_information", funi);
			var sf = new XmlRpc.Array (env);
				// XXX: args/vars or vars/args ?
				// vars
				var sfi = new XmlRpc.Array (env);
				foreach (var v in fun.vars)
					sfi.append_item (env, v.to_xmlrpc (env));
				sf.append_item (env, sfi);

				// args
				var sfi2 = new XmlRpc.Array (env);
				foreach (var a in fun.args)
					sfi.append_item (env, a.to_xmlrpc (env));
				sf.append_item (env, sfi2);
			ret.set_value (env, "stack_frame", sf);
		}

		return ret;
	}

	// TODO: must return true/false
	public bool upload(Target target) {
		XmlRpc.Value ret;
		var stru = new XmlRpc.Struct (env);
		stru.set_value (env, "username", user);
		stru.set_value (env, "password", pass);
		stru.set_value (env, "version", env.string_new (BC_VERSION));
		var fileinfo = new XmlRpc.Struct (env);
			fileinfo.set_value (env, "hash_md5", env.string_new (target.md5));
			fileinfo.set_value (env, "name", env.string_new (target.name));
			fileinfo.set_value (env, "description", env.string_new (target.description));
			fileinfo.set_value (env, "operating_system", env.string_new (
				"%d".printf (target.ostype)));
		stru.set_value (env, "file_information", fileinfo);
		var functions = new XmlRpc.Array (env);
		foreach (var f in target.functions)
			functions.append_item (env, get_function (target, f, true));
		// TODO: fill functions array with love
		stru.set_value (env, "functions", functions);
		var query = new XmlRpc.Array(env);
		query.append_item (env, stru);
		cli.call2 (env, si, "upload", query, out ret);
		if (env.fault_occurred) {
			// TODO: throw exception here
			print ("FAULT: %s\n", env.fault_string);
			return false;
		}

		// XXX: bug in vala, cannot cast out parameters
		XmlRpc.Array *aret = (XmlRpc.Array *)ret;
		int errcode;
		Integer? _errcode = (Integer?)aret->get_item (env, 0);
		_errcode.read (env, out errcode);
		//Integer? resplist = (Integer?)aret->get_item (env, 1);
		if (errcode != 0) {
			UploadReturn ur = (UploadReturn) errcode;
			print ("UploadReturn: %s\n", ur.to_string ());
			return false;
		}
		print ("SUCCESS!\n");
		return true;
	}

	public XmlRpc.Value download_overview(Target target) {
		// TODO: untested
		XmlRpc.Value ret;
		var stru = new XmlRpc.Struct(env);
		stru.set_value (env, "username", user);
		stru.set_value (env, "password", pass);
		stru.set_value (env, "version", env.string_new (BC_VERSION));
		var functions = new XmlRpc.Array (env);
		stru.set_value (env, "functions", functions);
		var query = new XmlRpc.Array(env);
		query.append_item (env, stru);
		cli.call2 (env, si, "download_overview", query, out ret);
		// TODO: parse reply here and proxy it to radaretarget instance
		return ret;
	}

	public bool download(Target target) {
		XmlRpc.Value ret;
		print ("=> bincrowd.download()\n");
		var stru = new XmlRpc.Struct(env);
		stru.set_value (env, "username", user);
		stru.set_value (env, "password", pass);
		stru.set_value (env, "version", env.string_new (BC_VERSION));
		var functions = new XmlRpc.Array (env);
		foreach (var f in target.functions) {
			functions.append_item (env, get_function (target, f, false));
			print ("FUN %s (bb=%u)\n", f.name, f.nodes.length ());
		}
		stru.set_value (env, "functions", functions);
		var query = new XmlRpc.Array(env);
		query.append_item (env, stru);
		cli.call2 (env, si, "download", query, out ret);
		// TODO: parse reply here and proxy it to radaretarget instance
		if (env.fault_occurred) {
			// TODO: throw exception here
			print ("FAULT: %s\n", env.fault_string);
			return false;
		}
		XmlRpc.Array *aret = (XmlRpc.Array *)ret;
		XmlRpc.String *sret = (XmlRpc.String*)aret->get_item (env, 1);
		string str;
		sret->read(env, out str);
		print ("REPLY: %s\n", str);
		return true;
	}

	public void print_value (XmlRpc.Value v) {
		XmlRpc.Type type = v.type ();
		switch (type) {
		case ARRAY:
			var a = (XmlRpc.Array*) v;
			int arsz = a->size (env);
			print ("Array [%d] = {\n", arsz);
			for (int i=0; i< arsz; i++) {
				XmlRpc.Value item = a->get_item (env, i);
				print ("  array[%d] = ", i);
				print_value (item);
				//print_value (env, env.array_get);
			}
			print ("}\n");
			break;
		case INT:
			int num;
			env.read_int(v, out num);
			print ("int(%d)\n", num);
			break;
		case STRING:
			unowned string str;
			env.read_string (v, out str);
			print ("string(%s)\n", str);
			break;
		case STRUCT:
			var s = (Struct*) v;
			print ("Struct size: %d\n", s->size (env));
			//env.struct_size (v);
			break;
		default:
			print ("Unknown data type %d\n", type);
			break;
		}
	}
}
}
