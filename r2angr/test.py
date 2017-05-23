import angr

# TODO take filename from r2pipe or env
p = angr.Project("/bin/ls")
cfg = None
for f in p.kb.functions:
	# print "Function %s"%(f)
	print ("af+ fcn_%s 0 %s"%(f, f))
	for b in p.kb.functions.get(f).blocks:
		print ("afb+ %s %s %d %s %s"%(f, b.addr, b.size))
		#print ("  %s %s"%(b.addr, b.size))

def read_memory():
	print p.kb.obj.memory.read_bytes(p.entry, 10)

def write_memory():
	print p.kb.obj.memory.write_bytes(p.entry, [1,2,3,4])

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
def syscmd(cmd):
	if cmd == "aslr":
		print (p.loader.aslr)
	if cmd == "aa":
		cfg = b.analyses.CFGAccurate(keep_state=True)
	if cmd == "afl":
		for f in p.kb.functions:
			print ("f fcn.0x%x=0x%x"%(f, f))
	elif cmd == "is":
		for a in p.kb.obj.symbols:
			print "%s %s"%(a.name, a.size)
	elif cmd == "iS":
		for a in p.kb.obj.segments:
			print("S %s %s %s %s %s %s"%(a.offset, a.vaddr, a.filesize, a.memsize, a.segname, prot(a.initprot)))
	elif cmd == "i":
		print("?e file.path=%s"%(p.kb.obj.binary))
		print("e asm.arch=%s"%(arch(p.kb.obj.arch.name)))
		print("e asm.bits=%s"%(p.kb.obj.arch.name))
		print("f angr.stack=0x%x"%(p.kb.obj.arch.initial_sp))
		print(p.kb.obj.imported_libraries)
	elif cmd == "il":
		print(p.kb.obj.imported_libraries)
