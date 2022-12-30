module pdv

import east
import json
import radare.r2

struct R2ijcore {
	file string
	size int
	fd   int
}

struct R2ij {
	core R2ijcore
}

pub struct RCore {}

fn plugin_call(coreptr voidptr, cmd &char) int {
	// eprintln('cal')
	core := r2.cast(coreptr)
	c := unsafe { cmd.vstring() }
	if c.starts_with('pdv') {
		core.cmd('?E decompiler not yet integrated')
		ij := core.cmd('ij')
		a := json.decode(R2ij, ij) or {
			eprintln('failed to decode ij JSON')
			return 0
		}
		eprintln(a.core.file)
		//
		r2p := r2.cast(core)
		mut e := east.new_program(r2p)
		fname := r2p.cmd('afi.')
		if fname.len > 0 {
			func := e.load_function(fname)
			e.optimize(func)
			kode := e.str_node(func)
			println(kode)
		} else {
			eprintln('No function?')
		}
		// e.free ()
		return 1
	}
	return 0
}

// definition

// ignored
[export: 'radare_plugin_function']
[manual_free]
fn radare_plugin_function() &C.r_lib_struct_t {
	pdv_plugin := &C.r_core_plugin_t{
		name: 'pdv'.str
		desc: 'the v decompiler for r2'.str
		license: 'MIT'.str
		call: plugin_call
	}
	unsafe {
		pp := C.malloc(1024) // too large
		C.memcpy(pp, pdv_plugin, 1024)
		p := &C.r_lib_struct_t{
			@type: C.R_LIB_TYPE_CORE
			data: pp // &pdv_plugin
			pkgname: 'pdv'.str
		}
		ppp := C.malloc(1024) // too large
		C.memcpy(ppp, p, 1024)
		return ppp
	}
	// C.fprintf(C.stderr, '%p\n'.str, p)
	// return p
}
