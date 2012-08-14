using GLib;

[CCode (cprefix="xmlrpc_", cheader_filename="xmlrpc-c/base.h,xmlrpc-c/client.h")]
namespace XmlRpc {
	[Compact]
	[CCode (cname="xmlrpc_client", free_function="xmlrpc_client_destroy", cprefix="xmlrpc_client_")]
	public class Client {
		public int version_major;
		public int version_minor;
		public int version_point;
		public static void init(int flags, string appname, string appversion);

		public static void create (Env env, int flags, string appname, string appversion, Value? parms, int nparms, out Client cli);

		[CCode (instance_pos=1.1)]
		public void call2(Env e, ServerInfo si, string method_name, Value param, out Value result);
		public static Value call_server(Env e, ServerInfo si, string method_name, string format, ...);
		public static Value call_server_params(Env e, ServerInfo si, string method_name, Value values);
		//TODO: static void init2()
		//static Value call(Env env, string url, string method_name, string format, ...);
		public void setup_global_const(Env e);
		public static void teardown_global_const();
	}

	public enum Flags {
		NO_FLAGS = 0,
		SKIP_LIBWWW_INIT = 1
	}

	[Compact]
	[CCode (cname ="xmlrpc_server_info", cprefix="xmlrpc_server_info_")]
	public class ServerInfo {
		public ServerInfo(Env env, string server_url);
		public ServerInfo copy(Env e);
		public void free();
		/* auth */
		[CCode (instance_pos=1.1)]
		public void set_basic_auth(Env e, string user, string pass);
		[CCode (instance_pos=1.1)]
		public void set_user(Env e, string user, string pass);
		[CCode (instance_pos=1.1)]
		public void allow_auth_basic(Env e);
		[CCode (instance_pos=1.1)]
		public void disallow_auth_basic(Env e);
		[CCode (instance_pos=1.1)]
		public void allow_auth_digest(Env e);
		[CCode (instance_pos=1.1)]
		public void disallow_auth_digest(Env e);
		[CCode (instance_pos=1.1)]
		public void allow_auth_negotiate(Env e);
		[CCode (instance_pos=1.1)]
		public void disallow_auth_negotiate(Env e);
		[CCode (instance_pos=1.1)]
		public void allow_auth_ntlm(Env e);
		[CCode (instance_pos=1.1)]
		public void disallow_auth_ntlm(Env e);
	}

	[Compact]
	[CCode (cprefix="xmlrpc_value_", cname = "xmlrpc_value", ref_function="xmlrpc_INCREF", unref_function="xmlrpc_DECREF", free_function="")]
	public class Value {
		public Type type();
	}

	[CCode (cname="xmlrpc_type", cprefix="XMLRPC_TYPE_")]
	public enum Type {
		INT,
		BOOL,
		DOUBLE,
		DATETIME,
		STRING,
		BASE64,
		ARRAY,
		STRUCT,
		C_PTR,
		NIL,
		I8,
		DEAD
	}

	[CCode (cname ="xmlrpc_env", cprefix="xmlrpc_env_", free_function="", destroy_function="xmlrpc_env_clean")]
	public struct Env {
		public string fault_string;
		public int fault_code;
		public bool fault_occurred;

		public Env();

		[CCode (cname="xmlrpc_parse_response")]
		public Value parse_response(string xmldata, int xmldata_len);

		/* create */
		public Value struct_new();
		public Value array_new();
		public Value bool_new(bool v);
		[CCode (cname="xmlrpc_string_new")]
		public Value string_new(string str);
		[CCode (cname="xmlrpc_int_new")]
		public Value int_new(int num);
		[CCode (cname="xmlrpc_double_new")]
		public Value double_new(double v);

		/* read */
		[CCode (cname="xmlrpc_read_bool")]
		public void read_bool(Value v, out bool num);
		[CCode (cname="xmlrpc_read_string")]
		public void read_string(Value v, out unowned string str);
		[CCode (cname="xmlrpc_read_int")]
		public void read_int(Value v, out int num);
		[CCode (cname="xmlrpc_read_double")]
		public void read_double(Value v, out double num);

		/* struct */
		// TODO: move into StructValue
		[CCode (cname="xmlrpc_struct_size")]
		public int struct_size(Value stru);
		[CCode (cname="xmlrpc_struct_has_key")]
		public bool struct_has_key(Value stru, string key);
		[CCode (cprefix="xmlrpc_")]
		public bool struct_has_key_n(Value stru, string key, int key_len);
		[CCode (cprefix="xmlrpc_")]
		public void struct_has_find_value(Value stru, string key, out Value v);
		[CCode (cprefix="xmlrpc_")]
		public void struct_has_find_value_v(Value stru, string key, out Value v);
		[CCode (cprefix="xmlrpc_")]
		public void struct_read_value(Value stru, string key, out Value v);
		[CCode (cprefix="xmlrpc_")]
		public void struct_read_value_v(Value stru, Value key, out Value v);
		[CCode (cprefix="xmlrpc_")]
		public Value struct_get_value(Value stru, string key);
		[CCode (cprefix="xmlrpc_")]
		public Value struct_get_value_n(Value stru, string key, int key_len);
		[CCode (cprefix="xmlrpc_")]
		public void struct_set_value(Value stru, string key, Value v);
		[CCode (cprefix="xmlrpc_")]
		public void struct_set_value_n(Value stru, string key, int key_len, Value v);
		[CCode (cprefix="xmlrpc_")]
		public void struct_set_value_v(Value stru, Value keyval, Value v);
		[CCode (cprefix="xmlrpc_")]
		public void struct_read_member(Value stru, int idx, out Value key, out Value v);
		[CCode (cprefix="xmlrpc_")]
		public void struct_get_key_and_value(Value stru, int idx, out Value key, out Value v);
	}

	// experimental //
	[CCode (cname="xmlrpc_value")]
	class Struct : Value {
		[CCode (cname="xmlrpc_struct_new", instance_pos=1.1)]
		public Struct (Env env);
		[CCode (cname="xmlrpc_struct_size", instance_pos=1.1)]
		public int size(Env env);
		[CCode (cname="xmlrpc_struct_set_value", instance_pos=1.1)]
		public void set_value(Env env, string key, Value v);
	}

	[CCode (cname="xmlrpc_value")]
	public class String : Value {
		[CCode (cname="xmlrpc_string_new")]
		public String(string str);
		[CCode (cname="xmlrpc_read_string", instance_pos=1.1)]
		public void read(Env env, out string value);
	}

	[CCode (cname="xmlrpc_value")]
	public class Integer : Value {
		[CCode (cname="xmlrpc_int_new")]
		public Integer(int num);
		[CCode (cname="xmlrpc_read_int", instance_pos=1.1)]
		public void read(Env env, out int value);
	}

	[CCode (cname="xmlrpc_value")]
	public class Array : Value {
		[CCode (cname="xmlrpc_array_new", instance_pos=1.1)]
		public Array (Env env);
		[CCode (cname="xmlrpc_array_size", instance_pos=1.1)]
		public int size(Env env);
		[CCode (cname="xmlrpc_array_get_item", instance_pos=1.1)]
		public Value get_item(Env env, int idx);
		[CCode (cname="xmlrpc_array_append_item", instance_pos=1.1)]
		public int append_item(Env env, Value b);
	}
}
