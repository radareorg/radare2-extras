using XmlRpc;

namespace Bincrowd {
	public class Argument {
		public string name;
		public string description;

		public Argument() {
			name = "";
			description = "";
		}

		// TODO : struct of size, name, description
		public XmlRpc.Value to_xmlrpc(Env env) {
			var item = new XmlRpc.Struct (env);
			item.set_value (env, "name", env.string_new (name));
			item.set_value (env, "description", env.string_new (description));
			item.set_value (env, "size", env.int_new (4)); // XXX: not yet implemented in radare
			return item;
		}
	}

	public class Variable : Argument { }
}
