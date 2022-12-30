module east

pub fn (mut e Program) str() string {
	return e.str_node(0)
}

pub fn (mut e Program) incdent(inc int) {
	e.indent_level += inc
}

pub fn (mut e Program) indent() string {
	mut s := []string{}
	for _ in 0 .. e.indent_level {
		s << ''
	}
	return s.join('  ')
}

pub fn (mut e Program) str_args(idx int) string {
	e.ast.find_type = ._argument
	s := e.str_code(idx)
	e.ast.find_type = ._none
	return s.trim_space().split('\n').join(', ')
}

pub fn (mut e Program) str_locals(idx int) string {
	e.ast.find_type = ._local
	s := e.str_code(idx)
	e.ast.find_type = ._none
	return s
}

pub fn (mut e Program) str_code(idx int) string {
	e.deep++
	if e.deep > 10 {
		eprintln('yamete kudasai')
		e.deep--
		return ''
	}
	mut s := []string{}
	n := e.node(idx)
	typ := e.ast.find_type
	match n.typ {
		._call {
			sym := e.str_code(n.children[0]).trim_space()
			arg := e.str_code(n.children[1]).trim_space()
			if typ == ._none {
				// s << e.indent()
				s << '$sym ($arg)'
			} else {
				s << sym
				s << arg
			}
		}
		._block {
			if n.children.len == 0 {
				// nothing
			} else if typ == ._none {
				s << '{\n'
				e.incdent(2)
				for c in n.children {
					e.indent()
					s << e.str_code(c) + '\n'
				}
				e.incdent(-2)
				s << e.indent() + '}\n'
			} else {
				for c in n.children {
					s << e.str_code(c)
				}
			}
		}
		._function {
			if typ == ._none {
				args := e.str_args(idx)
				s << 'fn ${n.name}($args) {\n'
				e.incdent(2)
				mut locals := []string{}
				for loc in e.str_locals(idx).split('\n') {
					if loc !in locals {
						if loc != '' {
							// TODO: use r2 to resolve type for this variable
							locals << loc
						}
					}
				}
				for loc in locals {
					s << e.indent()
					s << 'var $loc\n'
				}
				for c in n.children {
					s << e.indent()
					s << e.str_code(c) + '\n'
				}
				e.incdent(-2)
				s << '}\n'
			} else {
				for c in n.children {
					s << e.str_code(c)
				}
			}
		}
		._if {
			if typ == ._none {
				s << 'if '
				s << e.str_code(n.children[0])
				s << ' {\n'
				e.incdent(2)
				s << e.str_code(n.children[1])
				if n.children.len > 2 {
					// TODO: handle else if
					e.incdent(-2)
					s << e.indent()
					s << '} else {\n'
					e.incdent(2)
					s << e.str_code(n.children[2])
					e.incdent(-2)
					s << e.indent()
					s << '}\n'
				} else {
					e.incdent(-2)
					s << e.indent()
					s << '}\n'
				}
			} else {
				s << e.str_code(n.children[0])
				s << e.str_code(n.children[1])
				if n.children.len > 2 {
					s << e.str_code(n.children[2])
				}
			}
		}
		._comment {
			if typ == ._none {
				if n.name != '' {
					s << e.indent()
					s << '// $n.name '
				}
			}
		}
		._operation {
			if typ == ._none {
				s << e.indent()
				if _ := n.name.index('=') {
					s << e.str_code(n.children[0])
					s << ' $n.name '
					s << 'tmp'
				} else {
					s << 'tmp = '
					s << e.str_code(n.children[0])
					s << ' $n.name '
					// nn := e.node(n.children[1])
					// s << ' ($nn) '
					dos := e.str_code(n.children[1])
					if dos == '' {
						s << 'tmp'
					} else {
						s << dos
					}
				}
			}
		}
		._condition {
			if typ != ._none {
				for c in n.children {
					s << e.str_code(c)
				}
			} else {
				s << '('
				for c in n.children {
					s << e.str_code(c).trim_space()
				}
				s << ')'
			}
		}
		._while {
			if typ == ._none {
				s << 'while $n.name {\n'
				e.incdent(2)
				for c in n.children {
					s << e.indent()
					s << e.str_code(c) + '\n'
				}
				e.incdent(-2)
				s << '}\n'
			} else {
				for c in n.children {
					s << e.str_code(c)
				}
			}
		}
		._argument {
			if typ == ._none || typ == ._argument {
				s << '$n.name\n'
			}
		}
		._assign {
			if typ == ._none {
				s << e.indent()
				s << e.str_code(n.children[0]).trim_space()
				s << ' = '
				s << e.str_code(n.children[1]).trim_space()
			} else {
				s << e.str_code(n.children[0])
				s << e.str_code(n.children[1])
			}
		}
		._register, ._symbol {
			if typ == ._none {
				s << '$n.name'
			}
		}
		._number {
			if typ == ._none {
				s << '$n.name'
			}
		}
		._label {
			if typ == ._none && n.name != '' {
				s << e.indent() + '$n.name:\n'
			}
		}
		._string {
			if typ == ._none {
				s << '"$n.name"'
			}
		}
		._local {
			if typ == ._none || typ == ._local {
				name := '$n.name\n'
				if name !in s {
					s << name
				}
			}
		}
		else {
			// eprintln('Unhandled node $n')
		}
	}
	e.deep--
	return s.join('')
}

pub fn (mut e Program) str_node(idx int) string {
	n := e.node(idx)
	mut s := []string{}
	/*
	s << 'node_name: $n.name\n'
	for c in n.children {
		s << '- $c\n'
	}
	s << '## Nodes\n'
	for c in e.state().nodes {
		s << '- $c\n'
	}
	s << '## Decompilation\n'
	*/
	if n.typ == ._function {
		//
		s << e.str_code(idx)
	} else {
		eprintln('We can only start decompiling from a function')
	}
	return s.join('')
}
