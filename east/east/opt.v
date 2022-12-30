module east

pub fn (mut e Program) optimize(ni NodeIndex) {
	// run different levels of optimizations starting on given node
	// this function must replicate the code in print() to walk the ast
	// and find optimizations and modify the ast accordingly
	e.optimize_const(ni)
	//	e.optimize_empty(ni)
}

pub fn (mut e Program) optimize_const(ni NodeIndex) {
	// propagate constant values and fold unnecessary nodes
}

pub fn (mut e Program) optimize_empty(ni NodeIndex) {
	mut n := e.node(ni)
	mut children := []NodeIndex{}
	for c in n.children {
		cn := e.node(c)
		if cn.children.len >= 0 {
			e.del_child(ni, c)
			//	children << c
			children << c
		}
		// e.optimize_empty(c)
	}
	n.children = children
}
