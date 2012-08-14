using Bincrowd;

const string NAME = "XMLRPC Vala Auth Client";
const string SERVER = "http://invalidurl.com/RPC2";
const string VERSION = "1.0";

private void fail_if_fault(Env env) {
	if (env.fault_occurred) {
		stderr.printf ("FAIL: %s (%d)\n", env.fault_string,
			env.fault_code);
		Thread.exit (null);
	}
}

void print_value(Env env, XmlRpc.Value v) {
	XmlRpc.Type type = v.type ();
	switch (type) {
	case ARRAY:
		var a = (XmlRpc.Array*) v;
		int arsz = a->size (env);
		print ("Array [%d] = {\n", arsz);
		for (int i=0; i< arsz; i++) {
			XmlRpc.Value item = a->get_item (env, i);
			print ("  array[%d] = ", i);
			print_value (env, item);
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

XmlRpc.Value do_login(Env env, Client cli, ServerInfo si) {
	XmlRpc.Value ret;
	var stru = new XmlRpc.Struct(env);
	stru.set_value (env, "username", env.string_new ("myname"));
	stru.set_value (env, "password", env.string_new ("mypass"));
	stru.set_value (env, "version", env.string_new ("1"));
	var functions = new XmlRpc.Array (env);
	stru.set_value (env, "functions", functions);
	var query = new XmlRpc.Array(env);
	query.append_item (env, stru);
	cli.call2 (env, si, "download", query, out ret);
	return ret;
}

void main() {
	Client cli;
	print ("xmlrpc test program\n");

	var env = Env();
	Client.init (0, NAME, VERSION);
	Client.create (env, 0, NAME, VERSION, null, 0, out cli);

	var si = new ServerInfo (env, SERVER);
	fail_if_fault (env);

	si.set_basic_auth (env, "user", "pass");
	fail_if_fault (env);

	var v = do_login(env, cli, si);
	if (env.fault_occurred) {
		print ("Oops.. fault happenz (%s)\n", env.fault_string);
	} else {
		print ("type = %d (struct = %d)\n", v.type(), XmlRpc.Type.STRUCT);
		print_value (env, v);
	}
	
	si = null;
}
