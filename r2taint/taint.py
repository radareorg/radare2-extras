#!/usr/bin/python2
import r2pipe
import argparse

__author__ = "s0i37"
__version__ = 0.10

parser = argparse.ArgumentParser( description='static taint analysis' )
parser.add_argument("-reg", action="append", default=[], help='taint register')
parser.add_argument("-mem", action="append", default=[], help='taint memory')
parser.add_argument("-deep", type=int, default=1, help='max analysis deep')
parser.add_argument("-v", action="store_true", help='verbose')
parser.add_argument("--version", action="store_true", help='show version')
args = parser.parse_args()
r2 = r2pipe.open()


def get_sub_registers(register):
	register = register.lower()
	for sub_registers in [ 
			['rax', 'eax', 'ax', 'ah', 'al'],
			['rdx', 'edx', 'dx', 'dh', 'dl'],
			['rcx', 'ecx', 'cx', 'ch', 'cl'],
			['rbx', 'ebx', 'bx', 'bh', 'bl'],
			['rbp', 'esp', 'sp'],
			['rsp', 'ebp', 'bp'],
			['rdi', 'edi', 'di'],
			['rsi', 'esi', 'si'],
			['r8', 'r8d', 'r8w', 'r8b'],
			['r9', 'r9d', 'r9w', 'r9b'],
			['r10', 'r10d', 'r10w', 'r10b'],
			['r11', 'r11d', 'r11w', 'r11b'],
			['r12', 'r12d', 'r12w', 'r12b'],
			['r13', 'r13d', 'r13w', 'r13b'],
			['r14', 'r14d', 'r14w', 'r14b'],
			['r15', 'r15d', 'r15w', 'r15b'],
		]:
		if register in sub_registers:
			index = sub_registers.index(register)
			if index < 3:
				return sub_registers[index:] # AX has [AH,AL]
			else:
				return [sub_registers[index]] # AH hasn't AL
	return [register]

def taint_blacklist(instr):
	if instr["mnemonic"] in ("xor",):
		if instr["opex"]["operands"][0]["type"] == "reg" and instr["opex"]["operands"][1]["type"] == "reg":
			if instr["opex"]["operands"][0]["value"] == instr["opex"]["operands"][1]["value"]:
				return True
	else:
		return False

regs_taint = set()
mems_taint = set()
tainted = []
def taint(rip, instr, access):
	global regs_taint, mems_taint, tainted
	((regs_r, regs_w), (mems_r, mems_w)) = access
	is_propagation = False

	for reg_r in regs_r:
		if reg_r in regs_taint:
			is_propagation = True
	for mem_r in mems_r:
		if mem_r in mems_taint:
			is_propagation = True

	if taint_blacklist(instr):
		is_propagation = False

	if is_propagation:
		out = "[taint] {addr}: {instr}".format(addr=hex(rip), instr=instr["disasm"])
		if not out in tainted:
			tainted.append(out)
		if args.v:
			print out
		r2.cmd("ecHi yellow @{addr}".format(addr=rip))
		for reg_w in regs_w:
			if instr["mnemonic"] in ('push','pop'):
				if reg_w in ('rsp','esp','sp'):
					continue
			for reg in get_sub_registers(reg_w):
				regs_taint.add(reg)
		for mem_w in mems_w:
			mems_taint.add(mem_w)
	else:
		for reg_w in regs_w:		
			for reg in get_sub_registers(reg_w):
				if reg in regs_taint:
					regs_taint.remove(reg)
		for mem_w in mems_w:
			if mem_w in mems_taint:
				mems_taint.remove(mem_w)
				
	return is_propagation

def init_taint(args):
	global regs_taint, mems_taint
	regs_taint = set()
	mems_taint = set()
	ret = False
	for reg in args.reg:
		regs_taint.add(reg)
		ret = True
	for mem in args.mem:
		try:
			addr = int(mem, 16)
			mems_taint.add(addr)
			ret = True
		except:
			pass

		flag = get_flag_by_name(mem)
		if not flag:
			flag = get_flag_by_name("fcnvar." + mem)
		if flag:
			for i in xrange(flag["size"]):
				mems_taint.add(flag["offset"]+i)
				ret = True
	return ret


EIP = {16: "ip", 32: "eip", 64: "rip"}.get( r2.cmdj("ej")["asm.bits"] )
class Emu:
	def __init__(self):
		self.clean()
		self.init()
		self.rip = r2.cmdj("arj")[EIP]
		self.__idx = 0

	def __del__(self):
		self.clean()

	def init(self):
		r2.cmd("aei")
		r2.cmd("aeip")
		r2.cmd("aeim")
		r2.cmd("aets+")
		r2.cmd(".afv*")
		r2.cmd("e io.cache=1")

	def clean(self):
		r2.cmd("aei-;ar0")
		r2.cmd("dte-*")

	def goto(self, addr):
		r2.cmd("aepc %d" % addr)
		self.rip = addr

	def get_access(self):
		regs_r = set(); regs_w = set()
		mems_r = set(); mems_w = set()
		esil_trace_log = r2.cmd("dte").split('\n')
		esil_trace_log = filter(lambda l:l!='', esil_trace_log)
		self.__idx = int(esil_trace_log[-1][4:])
		for esil_event in esil_trace_log:
			if esil_event.startswith("%d." % self.__idx):
				if esil_event.find("mem.read.data") != -1:
					addr = int( esil_event.split("=")[0].split(".")[-1], 16)
					size = len( esil_event.split("=")[1] )/2
					for i in xrange(size):
						mems_r.add(addr+i)
				elif esil_event.find("mem.write.data") != -1:
					addr = int( esil_event.split("=")[0].split(".")[-1], 16)
					size = len( esil_event.split("=")[1] )/2
					for i in xrange(size):
						mems_w.add(addr+i)
				elif esil_event.find("reg.read=") != -1:
					for reg in esil_event.split("=")[1].split(','):
						regs_r.add(reg)
				elif esil_event.find("reg.write=") != -1:
					for reg in esil_event.split("=")[1].split(','):
						regs_w.add(reg)
		return ((regs_r, regs_w), (mems_r, mems_w))

	def get_regs(self):
		return r2.cmdj("arj")

	def step(self):
		r2.cmd("aes")
		self.rip = r2.cmdj("arj")[EIP]

def get_rip():
	return int(r2.cmd("s"), 16)

def set_rip(addr):
	r2.cmd("s {addr}".format(addr=addr))

def get_flag_by_addr(addr):
	return r2.cmdj("fdj @{addr}".format(addr=addr))

def get_flag_by_name(flag_name):
	for flag in r2.cmdj("fj"):
		if flag["name"].lower() == flag_name.lower() != -1:
			return flag

def next_instruction_addr(addr):
	return r2.cmdj("pdj 2@{addr}".format(addr=addr))[1]["offset"]

def get_n_instruction_addr(addr, num):
	return r2.cmdj("pdj {num}@{addr}".format(addr=addr, num=num))[-1]["offset"]

def get_instruction_size(addr):
	return r2.cmdj("aoj @{addr}".format(addr=addr))[0]["size"]

def disas(addr):
	return r2.cmdj("aoj @{addr}".format(addr=addr))[0]

def xrefs_from(addr):
	return r2.cmdj("axfj @{addr}".format(addr=addr))

def is_function(addr):
	return r2.cmdj("afdj @{addr}".format(addr=addr)) != {}

def get_function_range(addr):
	_range = set()
	for instr in r2.cmdj("pdrj @{addr}".format(addr=addr)) or {}:
		_range.add(instr["offset"])
	return _range

def get_function_jumps(addr):
	jumps = {}
	for xref in r2.cmdj("afxj @{addr}".format(addr=addr)):
		if xref["type"] == "code":
			if not xref["from"] in jumps:
				jumps[xref["from"]] = []
			jumps[xref["from"]].append(xref["to"]) 											# true case
			jumps[xref["from"]].append(xref["from"] + get_instruction_size(xref["from"]))	# false case
	return jumps

def get_function_end_addrs(addr):
	ends = []
	for bb in r2.cmdj("afbj @{addr}".format(addr=addr)):
		if not "jump" in bb:
			ends.append( get_n_instruction_addr(bb["addr"], bb["ninstr"]) )
	return ends

functions = []
def get_current_function(addr):
	global functions
	for function in functions:
		if addr in function.range:
			return function

	function = Function(addr)
	if function.range:
		functions.append(function)
		return function

class Function:
	def __init__(self, addr):
		self.range = get_function_range(addr)
		self.jumps = get_function_jumps(addr)
		self.ends = get_function_end_addrs(addr)


def main(args):
	origin = get_rip()
	path_constraint = None
	while True:
		emu = Emu()
		init_taint(args)
		deep = 0
		calle = 0
		branches = set()
		last_branch = None
		while deep >= 0:
			if deep > args.deep:
				break

			#r2.cmd("ecHi blue @%d" % emu.rip)

			function = get_current_function(emu.rip)
			if not function: # out of function
				break

			instr = disas(emu.rip)
			if args.v:
				print "[*][%d] 0x%x: %s" % (deep, emu.rip, instr["disasm"])
			
			if emu.rip in branches: # anti-loop
				break

			if emu.rip in function.jumps:
				branches.add(emu.rip)
				if emu.rip == path_constraint:
					function.jumps[emu.rip].pop(0)
				jump = function.jumps[emu.rip][0]

				if not function.jumps[emu.rip]:
					function.jumps[emu.rip].append(jump)

				if len(function.jumps[emu.rip]) > 1:
					last_branch = emu.rip

				if not emu.rip in function.ends:
					emu.step()
					#print "goto 0x%x (%d)" % (jump,jump)
					emu.goto(jump)
				else:
					#print "force return to 0x%x" % calle
					emu.goto(calle)
				continue

			if instr["mnemonic"] == "call":
				func_addr = int( xrefs_from(emu.rip)[0]["to"] )
				if get_flag_by_addr(func_addr).get("name","").find(".imp.") != -1 or is_function(func_addr) == False:
					emu.goto( next_instruction_addr(emu.rip) )
					continue
				if instr["disasm"].find("sym.__x86.get_pc_thunk.ax") == -1:
					deep += 1
					calle = next_instruction_addr(emu.rip)
			elif instr["mnemonic"] == "ret" or emu.rip in function.ends:
				deep -= 1

			rip = emu.rip
			emu.step()
			taint(rip, instr, emu.get_access())

		del(emu)
		set_rip(origin)
		path_constraint = last_branch
		if not path_constraint:
			break
		if args.v:
			print "path_constraint: 0x%x" % (path_constraint or 0)
		#if raw_input():
		#	break


if __name__ == '__main__':
	if args.version:
		print __version__
		exit()
	if args.reg == [] and args.mem == []:
		parser.print_help()
		exit()

	try:
		main(args)
	except KeyboardInterrupt:
		print "[!] interrupted"
	except:
		print "[!] something went wrong"

	if tainted:
		for t in tainted:
			print t
	else:
		print "[-] no taint"
