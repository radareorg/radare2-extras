# Example Python IO plugin written in Python
# ===========================================
#
#  -- pancake @ nopcode.org
#
# Usage:
#   r2 -I test-py-io.py pyio://33
#
# The r2lang.plugin function exposes a way to register new plugins
# into the RCore instance. This API is only available from RLang.
# You must call with with '#!python test.py' or 'r2 -i test.py ..'

import r2lang
import angr

FAKESIZE = 512

p = None
cfg = None


# TODO take filename from r2pipe or env
#p = angr.Project("/bin/ls")
#for f in p.kb.functions:
	# print "Function %s"%(f)
#	print ("af+ fcn_%s 0 %s"%(f, f))
#	for b in p.kb.functions.get(f).blocks:
#		print ("afb+ %s %s %d %s %s"%(f, b.addr, b.size))
		#print ("  %s %s"%(b.addr, b.size))

def arch(x):
	if x == "AMD64":
		return "x86"
	return x

def prot(x):
	if x == 7:
		return "mrwx"
	if x == 5:
		return "mr-x"
	if x == 3:
		return "mrw-"
	if x == 1:
		return "mr--"
	return "----"

# p.analyses.BackwardSlice    p.analyses.CFG              p.analyses.DFG              p.analyses.StaticHooker
# p.analyses.BinDiff          p.analyses.CFGAccurate      p.analyses.Disassembly      p.analyses.VFG
# p.analyses.BinaryOptimizer  p.analyses.CFGFast          p.analyses.GirlScout        p.analyses.VSA_DDG
# p.analyses.BoyScout         p.analyses.CongruencyCheck  p.analyses.LoopFinder       p.analyses.Veritesting
# p.analyses.CDG              p.analyses.DDG              p.analyses.Reassembler      p.analyses.reload_analyses
# 
def r2angr_cmd(cmd):
	if cmd == "?":
		print "=!?     - angr plugin help"
		print " aa     - analyze program"
		print " afl    - list all functions"
		print " afl*   - list all functions as r2 commands"
		print " i      - show target info"
		print " ie     - show entrypoint"
		print " is     - list symbols"
		print " iS     - list sections"
		print " il     - list libraries"
		return True
	if cmd == "aslr":
		print (p.loader.aslr)
		return True
	if cmd == "aa":
		cfg = p.analyses.CFGAccurate(keep_state=True)
		return True
	if cmd == "afl":
		for f in p.kb.functions:
			print ("f fcn.0x%x=0x%x"%(f, f))
		return True
	if cmd == "afl*":
		for f in p.kb.functions:
			print ("af+ fcn_%s 0 %s"%(f, f))
			for b in p.kb.functions.get(f).blocks:
				print ("afb+ %s %s %d %s %s"%(f, b.addr, b.size))
		return True
	if cmd == "ie":
		print ("f entry0 = 0x%x"%(p.entry))
		return
	if cmd == "is":
		for a in p.kb.obj.symbols:
			print "f sym.%s 0x%x %d"%(a.name, a.addr, a.size)
		return True
	if cmd == "iS":
		for a in p.kb.obj.segments:
			print("S %s %s %s %s %s %s"%(a.offset, a.vaddr, a.filesize, a.memsize, a.segname, prot(a.initprot)))
		return True
	if cmd == "i":
		print("?e file.path=%s"%(p.kb.obj.binary))
		print("e asm.arch=%s"%(arch(p.kb.obj.arch.name)))
		print("e asm.bits=%s"%(p.kb.obj.arch.name))
		print("f angr.stack=0x%x"%(p.kb.obj.arch.initial_sp))
		print(p.kb.obj.imported_libraries)
		return True
	if cmd == "il":
		for a in p.kb.obj.imported_libraries:
			print(a)
		return

def r2angr(a):
	def _open(path, rw, perm):
		global p
		print "Opening Angr project"
		p = angr.Project(path[7:])
		return 1234 
	def _check(path, many):
		return path[0:7] == "angr://"
	def _read(offset, size):
		return "".join(p.kb.obj.memory.read_bytes(0+offset, size))
	def _seek(offset, whence):
		if whence == 0: # SET
			return offset
		if whence == 1: # CUR
			return offset
		if whence == 2: # END
			return -1 
		return -1
	def _write(offset, data, size):
		p.kb.obj.memory.write_bytes(p.entry, data)
		print "python-write"
		return True
	def _system(cmd):
		r2angr_cmd(cmd)
		return 0 
	return {
		"name": "angr",
		"license": "GPL",
		"desc": "IO plugin for Angr (angr://[/path/to/file])",
		"check": _check,
		"open": _open,
		"read": _read,
		"seek": _seek,
		"write": _write,
		"system": _system,
	}

print r2lang.plugin("io", r2angr)
