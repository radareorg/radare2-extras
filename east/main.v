import east
import os
import cli { Command, Flag }
import radare.r2pipe

struct Options {
	esil string
	file string
	arch string
}

fn pdvtool() Options {
	mut cmd := Command{
		name: 'east'
		description: 'esil-ast based decompiler on top of r2'
		version: '0.0.1'
	}
	cmd.add_flag(Flag{
		flag: .string
		name: 'file'
		abbrev: 'f'
		description: 'program file to open'
	})
	cmd.add_flag(Flag{
		flag: .string
		name: 'esil'
		abbrev: 'e'
		description: 'esil expression to decompile'
	})
	/*
	mut test_cmd := Command{
		name: 'test'
		description: 'decompile an esil expression'
	}
	cmd.add_command(test_cmd)
	*/
	cmd.setup()
	cmd.parse(os.args)
	if os.args.len == 1 {
		exit(1)
	}
	mut arch := ''
	if e := cmd.flags.get_string('arch') {
		if e != '' {
			arch = e
		}
	}
	mut file := '-'
	if e := cmd.flags.get_string('file') {
		if e != '' {
			file = e
		}
	}
	mut esil := ''
	if e := cmd.flags.get_string('esil') {
		if e != '' {
			esil = e
		}
	}
	return Options{
		arch: arch
		esil: esil
		file: file
	}
}

fn main() {
	mut opt := pdvtool()
	println(opt)
	if opt.esil != '' {
		main_hello(opt)
	} else {
		main_hello(opt)
		main_hello2()
		main_hello3()
	}
}

fn main_hello(opt Options) {
	r2 := r2pipe.spawn(opt.file, '') or {
		eprintln('r2pipe.spawn: $err')
		exit(1)
	}
	if opt.arch != '' {
		r2.cmd('e asm.arch=$opt.arch')
	}
	esil := if opt.esil == '' { '1,eax,:=' } else { opt.esil }
	mut program := east.new_program(r2)
	mut statements := []east.NodeIndex{}
	statements << program.new_statement('0x1000', esil)
	mut function := program.new_function('test', statements)
	kode := program.str_node(function)
	println(kode)
}

fn main_hello2() {
	r2 := r2pipe.spawn('test/bins/hello', '') or {
		eprintln('r2pipe.spawn: $err')
		exit(1)
	}
	mut program := east.new_program(r2)

	func := program.load_function('main')
	// test adding node
	{
		var_res := program.new_local(4, 'res')
		var_rus := program.new_local(4, 'rus')
		res_byebye := program.add(._assign, [var_res, var_rus])
		program.add_child(func, res_byebye)
	}
	kode := program.str_node(func)
	println(kode)
	exit(0)
}

fn main_hello3() {
	r2 := r2pipe.spawn('test/bins/hello', '') or {
		eprintln('r2pipe.spawn: $err')
		exit(1)
	}
	mut e := east.new_program(r2)
	// e.on('reg_read', fn (name) => { if name == 'PC' { } })

	/*
	e.add_symbol('esi', 'arg0')
	e.add_symbol('rsi', 'arg0')
	e.add_symbol('esi', 'arg1')
	e.add_symbol('rsi', 'arg1')

	if s := e.find_symbol('rsi') {
		println('arg0 is accessed')
		// e.propagate_symbol()
	}
	*/

	for _ in 0 .. 10 {
		pc := e.pc()
		e.step()
		expr := e.expr(pc)
		e.eval(0, expr)
		eprintln('before($pc) now($e.pc()) $expr')
	}

	/*
	e.add_type('int', 'int')
	e.add_type('hello_t', 'struct { int msg; }')
	*/

	sym_puts := e.add_symbol(0x808080, 'puts')
	sym_win := e.add_string(0, 'win')
	sym_fail := e.add_string(0, 'fail')

	cn_bb_true := e.add(._block, [
		e.add(._call, [sym_puts, sym_win]),
	])
	cn_bb_false := e.add(._block, [
		e.add(._call, [sym_puts, sym_fail]),
	])

	arg_argc := e.add_argument(0, 'argc')
	cn_cmp := e.add(._condition, [
		arg_argc,
		e.add_operation('<'),
		e.add_number(10),
	])
	ifelse := e.add(._if, [
		cn_cmp,
		cn_bb_true,
		cn_bb_false,
	])

	sym_byebye := e.add_string(0, 'byebye')
	call_byebye := e.add(._call, [sym_puts, sym_byebye])

	var_res := e.new_local(4, 'tmp')
	res_byebye := e.add(._assign, [var_res, call_byebye])

	sym_exit := e.add_symbol(0, 'exit')
	call_exit := e.add(._call, [sym_exit, var_res])

	n_func := e.add(._function, [
		ifelse,
		res_byebye,
		call_exit,
	])
	e.node(n_func).name = 'main'

	// optimize function
	e.optimize(n_func)

	code := e.str_node(n_func)
	println(code)
	r2.cmd('q')
}
