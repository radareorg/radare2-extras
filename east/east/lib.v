module east

/*
struct EsilOperation {
	name string
}
*/

type EsilOperationCallback = fn (e Program) bool

struct EsilOperation {
mut:
	cb EsilOperationCallback
}

enum EsilType {
	number
	register
	command
}

struct EsilState {
mut:
	// esil
	pos       int
	last_node int
	tokens    []string
}

struct East {
pub mut:
	// ast
	nodes       []Node
	in_function int
	find_type   NodeStatement
}

pub interface R2PipeInterface {
	cmd(a string) string
}

// TODO: rename to Program
struct Program {
	a  int
	r2 R2PipeInterface
mut:
	deep        int
	stack       []string
	stack_index []NodeIndex
	states      []EsilState
	ops         map[string]EsilOperation
	// codegen
	ast          East
	indent_level int
}

pub fn new_program(r2 R2PipeInterface) Program {
	mut e := Program{0, r2, 0, []string{}, []NodeIndex{}, []EsilState{}, map[string]EsilOperation{}, East{}, 0}
	// XXX unused ops
	e.ops['+'] = EsilOperation{fn (e Program) bool {
		// pop 2
		println('add')
		return true
	}}
	e.ops['-'] = EsilOperation{fn (e Program) bool {
		// pop 2
		println('sub')
		return true
	}}
	return e
}

pub fn (mut e Program) load_instruction(ni NodeIndex, addr string, expr string) NodeIndex {
	// add label
	return e.eval(ni, expr)
}

pub fn (mut program Program) new_statement(addr string, esil string) NodeIndex {
	block := program.add_name(._block, addr, [])
	program.add_child(block, program.add_name(._comment, esil, []))
	program.add_child(block, program.add_label(addr))
	return program.load_instruction(block, addr, esil)
}

pub fn (mut e Program) new_function(name string, statements []NodeIndex) NodeIndex {
	return e.add_name(._function, name, statements)
}

pub fn (mut e Program) load_function(name string) NodeIndex {
	e.load_at(name)
	mut statements := []NodeIndex{}
	for expr in e.r2.cmd('pief').split('\n') {
		addr := expr.split(' ')
		esil := if addr.len > 1 { addr[1] } else { '' }
		statements << e.new_statement(addr[0], esil)
	}
	return e.new_function(name, statements)
}

pub fn (mut e Program) load_function2(name string) NodeIndex {
	mut statements := []NodeIndex{}
	e.load_at(name)
	bbs := e.r2.cmd('afb@$name').trim_space()
	for bb in bbs.split('\n') {
		bbw := bb.split(' ')
		addr := bbw[0]
		mut addr_j := ''
		mut addr_f := ''
		for j in 0 .. bbw.len {
			if bbw[j] == 'j' {
				addr_j = bbw[j + 1]
			}
			if bbw[j] == 'f' {
				addr_f = bbw[j + 1]
			}
		}
		println('$addr -> $addr_j -> $addr_f ')
		ni := e.add_block(addr)
		if addr_j == '' {
			// return basic block
			e.add_child(ni, e.add_return(''))
		} else if addr_f == '' {
			// only true jump
			e.add_child(ni, e.add_goto(addr_j))
		} else {
			// have true and false jumps
			e.add_child(ni, e.add_goto(addr_j))
			e.add_child(ni, e.add_goto(addr_f))
		}
		statements << ni
	}
	eprintln(statements)
	return e.new_function(name, statements)
}

pub fn (mut e Program) load_at(a string) bool {
	e.r2.cmd('aeim;ar0;aei')
	e.r2.cmd('s $a;af;aepc $$')
	return true
}

pub fn (mut e Program) is_operation(op string) ?EsilOperation {
	if op in e.ops {
		return e.ops[op]
	}
	return error('no op')
}

pub fn (mut e Program) step() bool {
	expr := e.r2.cmd('aoeq@r:PC')
	for tok in expr.split(',') {
		println('$tok')
		op := e.is_operation(tok) or {
			eprintln('oops')
			eprintln(err)
			break
		}
		eprintln(op)
	}
	e.r2.cmd('ar PC=PC+\$l@r:PC')
	// e.r2.cmd('aes')
	return true
}

pub fn (mut e Program) expr(addr string) string {
	return e.r2.cmd('aoeq@$addr').trim_space()
}

pub fn (mut e Program) find_type() EsilType {
	s := e.state().tokens[e.state().pos]
	// b := if s.len > 0 { s[0] } else { 0 }
	if s != '' && s[0] >= `0` && s[0] <= `9` {
		return .number
	}
	return match s {
		'+', '-' {
			.command
		}
		else {
			.register
		}
	}
}

pub fn (mut e Program) find_statement_type() NodeStatement {
	s := e.state().tokens[e.state().pos]
	// b := if s.len > 0 { s[0] } else { 0 }
	if s != '' && s[0] >= `0` && s[0] <= `9` {
		return ._number
	}
	return match s {
		'+', '+=', '!', '-', '|', '&', '&=', '-=', '*', '*=', '/', '%', '^', '^=', '<<', '>>',
		'<<<', '<<<<', '>>>', '>>>>' {
			._operation
		}
		'=[8]', '=[4]', '=[2]', '=[1]' {
			._operation
		}
		'[8]', '[4]', '[2]', '[1]' {
			._assign
		}
		'=', ':=' {
			._assign
		}
		'GOTO' {
			._goto
		}
		'==', '!=' {
			._condition
		}
		else {
			._symbol
		}
	}
}

pub fn (mut e Program) push_state() {
	e.states << EsilState{}
}

pub fn (mut e Program) pop_state() {
	e.states.pop()
}

pub fn (mut e Program) pop_index() NodeIndex {
	if e.stack_index.len == 0 {
		return 0
	}
	return e.stack_index.pop()
}

pub fn (mut e Program) pop() string {
	if e.stack.len == 0 {
		return ''
	}
	return e.stack.pop()
}

pub fn (mut e Program) push_index(s NodeIndex) {
	e.stack_index << s
}

pub fn (mut e Program) push(s string) {
	e.stack << s
}

pub fn (mut e Program) state() &EsilState {
	if e.states.len == 0 {
		e.push_state()
	}
	return &e.states[e.states.len - 1]
}

pub fn (mut e Program) eval(ni NodeIndex, esil string) NodeIndex {
	e.push_state()
	e.state().pos = 0
	e.stack = []
	e.state().tokens = esil.split(',')
	pc := e.pc().u64()
	for pos in 0 .. e.state().tokens.len {
		e.state().pos = pos
		// create node for token nth
		node := e.cur_node()
		// dump(node)
		match node.typ {
			._operation {
				if false {
					dst := e.pop_index()
					src := e.pop_index()
					// pc := '${e.pc()}.$e.state().pos'.u64()
					eqop := e.add_name(._operation, node.name, [
						dst,
						src,
					])
					// e.add_symbol(pc, dst), e.add_symbol(pc, src), ])
					e.add_child(ni, eqop)
				} else {
					dst := e.pop()
					src := e.pop()
					// pc := '${e.pc()}.$e.state().pos'.u64()
					eqop := e.add_name(._operation, node.name, [
						e.add_symbol(pc, dst),
						e.add_symbol(pc, src),
					])
					// e.add_symbol(pc, dst), e.add_symbol(pc, src), ])
					e.add_child(ni, eqop)
				}
			}
			._condition {}
			._assign {
				dst := e.pop()
				src := e.pop()
				// eprintln('assign $src $dst')
				if false {
					_ := e.add_name(._register, dst, [])
					_ := e.add_name(._register, src, [])
					var_res := e.new_local(4, 'res')
					var_rus := e.new_local(4, 'rus')
					res_byebye := e.add(._assign, [var_res, var_rus])
					e.add_child(ni, res_byebye)
				}
				eqop := e.add(._assign, [
					e.add_symbol(pc, dst),
					e.add_symbol(pc, src),
				])
				e.add_child(ni, eqop)
			}
			._symbol {
				//
				e.push(node.name)
				e.push_index(pos)
			}
			._goto {
				// process and convert
			}
			._number {
				//
				e.push(node.name)
				e.push_index(pos)
			}
			else {
				eprintln('unk $node.name')
			}
		}
		// dump(node)
		e.state().pos++
	}
	e.pop_state()
	return ni
}

pub fn (mut e Program) cur_node() &Node {
	mut n := &Node{}
	n.typ = e.find_statement_type()
	/*
	e.state().push('')
	e.state().pop()
	*/
	n.addr = e.pc()
	n.pos = e.state().pos
	n.name = e.state().tokens[n.pos]
	return n
}

pub fn (e Program) pc() string {
	return e.r2.cmd('ar?PC').trim_space()
}
