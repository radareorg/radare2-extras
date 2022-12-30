module east

pub enum NodeStatement {
	_none
	_break
	_switch
	_comment
	_case
	_block
	_if
	_condition
	_symbol
	_register
	_string
	_local
	_operation // + - < > << || ...
	_return
	_function
	_else
	_for
	_argument
	_while
	_dowhile
	_call
	_number // number
	_goto // symbol or label
	_label // symbol
	_assign // dst, src
	_oparen
	_cparen
}

pub struct Node {
pub mut:
	name string
	typ  NodeStatement
	// typ      EsilType
	addr     string
	pos      int
	parent   int
	children []NodeIndex
}

type NodeIndex = int

pub fn (mut e Program) add_name(typ NodeStatement, name string, nodes []NodeIndex) NodeIndex {
	ni := e.new_node(name)
	mut n := e.node(ni)
	n.typ = typ
	n.children = nodes
	return ni
}

pub fn (mut e Program) add(typ NodeStatement, nodes []NodeIndex) NodeIndex {
	return e.add_name(typ, '?', nodes)
}

pub fn (mut e Program) add_operation(name string) NodeIndex {
	ni := e.new_node(name)
	mut n := e.node(ni)
	n.typ = ._operation
	return ni
}

pub fn (mut e Program) add_block(addr string) NodeIndex {
	ni := e.new_node(addr)
	mut n := e.node(ni)
	n.typ = ._block
	return ni
}

pub fn (mut e Program) add_goto(addr string) NodeIndex {
	ni := e.new_node(addr)
	mut n := e.node(ni)
	n.typ = ._goto
	return ni
}

pub fn (mut e Program) add_return(arg string) NodeIndex {
	ni := e.new_node(arg)
	mut n := e.node(ni)
	n.typ = ._return
	return ni
}

pub fn (mut e Program) add_label(addr string) NodeIndex {
	ni := e.new_node(addr)
	mut n := e.node(ni)
	n.typ = ._label
	return ni
}

pub fn (mut e Program) add_number(addr u64) NodeIndex {
	ni := e.new_node('$addr')
	mut n := e.node(ni)
	n.typ = ._number
	return ni
}

pub fn (mut e Program) add_argument(addr u64, name string) NodeIndex {
	ni := e.new_node('$name')
	mut n := e.node(ni)
	n.typ = ._argument
	return ni
}

pub fn (mut e Program) add_symbol(addr u64, name string) NodeIndex {
	ni := e.new_node('$name')
	mut n := e.node(ni)
	n.typ = ._symbol
	return ni
}

pub fn (mut e Program) add_string(addr u64, name string) NodeIndex {
	ni := e.new_node('$name')
	mut n := e.node(ni)
	n.typ = ._string
	return ni
}

pub fn (mut e Program) new_local(addr u64, name string) NodeIndex {
	ni := e.new_node('$name')
	mut n := e.node(ni)
	n.typ = ._local
	// f := e.node(e.state().in_function)
	return ni
}

pub fn (mut e Program) new_node(name string) NodeIndex {
	mut n := &Node{}
	n.parent = e.state().last_node
	n.name = name
	n.addr = e.pc()
	n.pos = e.state().pos
	e.ast.nodes << n
	return e.ast.nodes.len - 1
}

pub fn (mut e Program) node(n int) &Node {
	return &e.ast.nodes[n]
}

// XXX not working as expected
pub fn (mut e Program) del_child(n int, c int) {
	if n < 0 || n >= e.ast.nodes.len {
		return
	}
	for i, _ in e.node(n).children {
		cn := e.node(n).children[int(i)]
		if cn == c {
			eprintln('$cn vs $c')
			mut nn := e.node(n)
			if nn.children.len < 1 {
				eprintln('delete')
				// nn.children.delete(idx)
			}
			// dump(e.node(e.ast.nodes[n].children)
			//	break
		}
	}
}

pub fn (mut e Program) add_child(n int, c int) {
	e.ast.nodes[n].children << c
}

pub fn (mut e Program) new_node_condition(name string, a int, b int) {
}
