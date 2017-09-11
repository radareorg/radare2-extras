import r2lang
import r2pipe
import triton
import struct
import string
import collections

class R2(object):
    def __init__(self, name):
        self.name = name

        self.r2 = r2pipe.open()

        bininfo = self.r2.cmdj("ij")["bin"]
        self.arch = bininfo["arch"]
        self.bits = bininfo["bits"]
        self.regs = self.r2.cmdj("drlj")
        self.switch_flagspace(self.name)

        self.sections = self.get_sections()
        imports = self.get_imports()
        self.imports = {}
        for imp in imports:
            self.imports[imp["plt"]] = imp["name"]
        exports = self.get_exports()
        self.exports = {}
        for exp in exports:
            self.exports[exp["name"]] = exp["vaddr"]

    def get_reg(self, reg):
        return self.get_regs()[reg]

    def get_regs(self):
        return self.r2.cmdj("drj")

    def get_maps(self):
        return self.r2.cmdj("dmj")

    def get_sections(self):
        return self.r2.cmdj("Sj")

    def get_imports(self):
        return self.r2.cmdj("iij")

    def get_exports(self):
        return self.r2.cmdj("iEj")

    def read_mem(self, address, size):
        hexdata = self.r2.cmd("p8 {} @ {:#x}".format(size, address))
        return hexdata.decode('hex')

    def write_mem(self, address, data):
        self.r2.cmd("wx {} @ {:#x}".format(data.encode("hex"), address))

    def seek(self, addr=None):
        if addr:
            self.r2.cmd("s {:#x}".format(addr))
        return int(self.r2.cmd("s"), 16)

    def switch_flagspace(self, name):
        self.r2.cmd("fs {}".format(name))

    def set_flag(self, section, name, size, address):
        name = "{}.{}.{}".format(self.name, section, name)
        self.r2.cmd("f {} {} @ {}".format(name, size, address))

    def get_flags(self, section=None):
        flags = {}
        for flag in self.r2.cmdj("fj"):
            name = flag["name"]
            offset = flag["offset"]
            if section and name.startswith("{}.{}.".format(self.name, section)):
                flags[name] = offset
            elif not section:
                flags[name] = offset
        return flags
    def set_comment(self, comment, address=None):
        if address:
            self.r2.cmd("CC- @ {:#x}".format(address))
            self.r2.cmd("CC {} @ {:#x}".format(comment, address))
        else:
            self.r2.cmd("CC-".format(comment))
            self.r2.cmd("CC {}".format(comment))

    def integer(self, s):
        regs = self.get_regs()
        flags = self.get_flags()
        if s in regs:
            v = regs[s]
        elif s in flags:
            v = flags[s]
        elif s in self.exports:
            v = self.exports[s]
        elif s.startswith("0x"):
            v = int(s, 16)
        else:
            v = int(s)
        return v

tritonarch = {
    "x86": {
        32: triton.ARCH.X86,
        64: triton.ARCH.X86_64
    }
}

class Pimp(object):
    CMD_HANDLED = 1
    CMD_NOT_HANDLED = 0
    def __init__(self, context=None):
        self.r2p = None
        self.comments = {}
        self.arch = None
        self.inputs = collections.OrderedDict()
        self.regs = {}
        self.triton_regs = {}
        self.commands = {}
        self.last_symjump = None
        self.input_type = None

        self.r2p = R2("pimp")
        arch = self.r2p.arch
        bits = self.r2p.bits
        self.arch = tritonarch[arch][bits]
        self.trace = collections.Counter()


        triton.setArchitecture(self.arch)
        triton.setAstRepresentationMode(triton.AST_REPRESENTATION.PYTHON)

        # Hack in order to be able to get triton register ids by name
        for r in triton.getAllRegisters():
            self.triton_regs[r.getName()] = r

        if self.arch == triton.ARCH.X86:
            self.pcreg = triton.REG.EIP
        elif self.arch == triton.ARCH.X86_64:
            self.pcreg = triton.REG.RIP
        else:
            raise(ValueError("Architecture not implemented"))

        setattr(self.memoryCaching, "memsolver", self.r2p)

    def pimpcmd(self, name):
        def dec(func):
            self.commands[name] = (func)
        return dec

    def handle(self, command, args):
        self.r2p.switch_flagspace(self.r2p.name)
        if command in self.commands:
            return self.commands[command](self, args)
        print "[!] Unknown command {}".format(command)

    def reset(self):
        triton.resetEngines()
        triton.clearPathConstraints()
        triton.setArchitecture(self.arch)

        triton.enableMode(triton.MODE.ALIGNED_MEMORY, True)
        triton.enableMode(triton.MODE.ONLY_ON_SYMBOLIZED, True)

        triton.addCallback(self.memoryCaching,
                           triton.CALLBACK.GET_CONCRETE_MEMORY_VALUE)
        triton.addCallback(self.constantFolding,
                           triton.CALLBACK.SYMBOLIC_SIMPLIFICATION)

        for r in self.regs:
            if r in self.triton_regs:
                triton.setConcreteRegisterValue(
                    triton.Register(self.triton_regs[r], self.regs[r] & ((1 << self.triton_regs[r].getBitSize()) - 1))
                )

        for m in cache:
            self.write_mem(m['start'], m["data"])

        for address in self.inputs:
                self.inputs[address] = triton.convertMemoryToSymbolicVariable(
                    triton.MemoryAccess(
                        address,
                        triton.CPUSIZE.BYTE
                    )
                )

    # Triton does not handle class method callbacks, use staticmethod.
    @staticmethod
    def memoryCaching(mem):
        addr = mem.getAddress()
        size = mem.getSize()
        mapped = triton.isMemoryMapped(addr)
        if not mapped:
            dump = pimp.memoryCaching.memsolver.read_mem(addr, size)
            triton.setConcreteMemoryAreaValue(addr, bytearray(dump))
            cache.append({"start": addr, "data": bytearray(dump)})
        return

    @staticmethod
    def constantFolding(node):
        if node.isSymbolized():
            return node
        return triton.ast.bv(node.evaluate(), node.getBitvectorSize())

    def get_current_pc(self):
        return triton.getConcreteRegisterValue(self.pcreg)

    def disassemble_inst(self, pc=None):

        _pc = self.get_current_pc()
        if pc:
            _pc = pc

        opcodes = self.read_mem(_pc, 16)

        # Create the Triton instruction
        inst = triton.Instruction()
        inst.setOpcodes(opcodes)
        inst.setAddress(_pc)
        # disassemble instruction
        triton.disassembly(inst)
        return inst

    def inst_iter(self, pc=None):

        while True:
            inst = self.process_inst()
            if inst.getType() == triton.OPCODE.HLT:
                break
            yield inst

    def process_inst(self, pc=None):
        _pc = self.get_current_pc()
        if pc:
            _pc = pc

        opcodes = self.read_mem(_pc, 16)

        # Create the Triton instruction
        inst = triton.Instruction()
        inst.setOpcodes(opcodes)
        inst.setAddress(_pc)
        # execute instruction
        triton.processing(inst)
        return inst

    def add_input(self, addr, size):
        for offset in xrange(size):
            self.inputs[addr + offset] = triton.convertMemoryToSymbolicVariable(
                triton.MemoryAccess(
                    addr + offset,
                    triton.CPUSIZE.BYTE
                )
            )

    def is_conditional(self, inst):
        return inst.getType() in (triton.OPCODE.JAE, triton.OPCODE.JA, triton.OPCODE.JBE, triton.OPCODE.JB, triton.OPCODE.JCXZ, triton.OPCODE.JECXZ, triton.OPCODE.JE, triton.OPCODE.JGE, triton.OPCODE.JG, triton.OPCODE.JLE, triton.OPCODE.JL, triton.OPCODE.JNE, triton.OPCODE.JNO, triton.OPCODE.JNP, triton.OPCODE.JNS, triton.OPCODE.JO, triton.OPCODE.JP, triton.OPCODE.JS)

    def symulate(self, stop=None, stop_on_sj=False, stop_on_si=False):
        while True:
            inst = self.disassemble_inst()
            print inst
            if inst.getAddress() == stop or inst.getType() == triton.OPCODE.HLT:
                return inst.getAddress()

            inst = self.process_inst()
            isSymbolized = inst.isSymbolized()
            if isSymbolized:
                for access, ast in inst.getLoadAccess():
                    if(access.getAddress() in self.inputs):
                        try:
                            if str(access) == str(inst.getSecondOperand()):
                                self.r2p.r2.cmd("ecHw '{}' red @ {:#x}".format(self.r2p.r2.cmd("e scr.color=false; pi 1 @ {:#x}; e scr.color=true".format(inst.getAddress())).split(",")[1].lstrip().rstrip(), inst.getAddress()))
                            elif str(access) == str(inst.getThirdOperand()):
                                print self.r2p.r2.cmd("e scr.color=false; pi 1 @ {:#x}; e scr.color=true".format(inst.getAddress())).split(",", 2)
                        except: pass
                        self.comments[inst.getAddress()] = "symbolized memory: {:#x}".format(access.getAddress())
                rr = inst.getReadRegisters()
                if rr:
                    reglist = []
                    for r, ast in rr:
                        if ast.isSymbolized():
                            reglist.append(r.getName())
                            self.r2p.r2.cmd("ecHw {} red @ {:#x}".format(r.getName(), inst.getAddress()))
                    self.comments[inst.getAddress()] = "symbolized regs: {}".format(", ".join(reglist))


            if stop_on_si == True and isSymbolized:
                return inst.getAddress()
            if (stop_on_sj == True and isSymbolized and inst.isControlFlow() and (inst.getType() != triton.OPCODE.JMP)):
                return inst.getAddress()

    def process_constraint(self, cstr):
        global cache
        # request a model verifying cstr
        model = triton.getModel(cstr)
        if not model:
            return False

        # apply model to memory cache
        for m in model:
            for address in self.inputs:
                if model[m].getId() == self.inputs[address].getId():
                    nCache = []
                    for c in cache:
                        if c["start"] <= address < c["start"] + len(c["data"]):
                            c["data"][address-c["start"]] = model[m].getValue()
                        nCache.append(c)
                    cache = nCache

        return True

    def build_jmp_constraint(self, pc=None, take=True):
        _pc = self.get_current_pc()
        if pc:
            _pc = pc

        inst = self.disassemble_inst(_pc)
        if take:
            target = inst.getFirstOperand().getValue()
        else:
            target = _pc + inst.getSize()

        pco = triton.getPathConstraints()
        cstr = triton.ast.equal(triton.ast.bvtrue(), triton.ast.bvtrue())

        for pc in pco:
            if pc.isMultipleBranches():
                branches = pc.getBranchConstraints()
                for branch in branches:

                    taken = branch["isTaken"]
                    src = branch["srcAddr"]
                    dst = branch["dstAddr"]
                    bcstr = branch["constraint"]

                    isPreviousBranchConstraint = (src != _pc) and taken
                    isBranchToTake =  src == _pc and dst == target

                    if isPreviousBranchConstraint or isBranchToTake:
                        cstr = triton.ast.land(cstr, bcstr)

        if self.input_type == "string":
            addrs = [self.inputs[inpt] for inpt in self.inputs]
            for inpt in addrs[0:-1]:
                symExp = triton.getSymbolicExpressionFromId(inpt.getId()).getAst()
                cstr = triton.ast.land(cstr, triton.ast.lnot(triton.ast.equal(symExp, triton.ast.bv(0, 8))))

        cstr = triton.ast.assert_(cstr)
        return cstr

    def peek(self, addr, size):
        return triton.getConcreteMemoryValue(triton.MemoryAccess(addr, size))

    def poke(self, addr, size, value):
        return triton.setConcreteMemoryValue(triton.MemoryAccess(addr, size, value))

    def read_mem(self, addr, size):
        return triton.getConcreteMemoryAreaValue(addr, size)

    def write_mem(self, addr, data):
        triton.setConcreteMemoryAreaValue(addr, data)

    def read_str(self, addr):
        s = str()
        i = 0
        while (True):
            v = self.peek(addr + i, 1)
            s += chr(v)
            if not v: break
        return s

    @staticmethod
    def isMapped(addr):
        for m in cache:
            if m["start"] <= addr < m["start"] + len(m["data"]):
                return True
        return False

    def plugin(self, a):
        def _call(s):
            try:
                args = s.split()
                module, command = args[0].split(".")
            except:
                # exit slently, this is not for us
                return Pimp.CMD_NOT_HANDLED
            try:
                if module == "pimp":
                    self.handle(command, args[1:])
                    for r in self.triton_regs:
                        self.r2p.set_flag("regs", r, self.triton_regs[r].getSize(), triton.getConcreteRegisterValue(self.triton_regs[r]) )
                    return Pimp.CMD_HANDLED
                # not for us
                return Pimp.CMD_NOT_HANDLED
            except Exception as e:
                # this is an actual pimp error.
                print e
                return Pimp.CMD_HANDLED

        return {
            "name": "pimp",
            "licence": "GPLv3",
            "desc": "Triton based plugin for concolic execution and total control",
            "call": _call,
        }

cache = []
pimp = Pimp()

def get_byte(address):
    for m in cache:
        if m["start"] <= address < m["start"] + len(m["data"]):
            idx = address - m["start"]
            return struct.pack("B", m["data"][idx])


# initialise the Triton context with current r2 state (registers)
@pimp.pimpcmd("init")
def cmd_init(p, a):
    p.regs = p.r2p.get_regs()
    p.reset()

# continue until address
@pimp.pimpcmd("dcu")
def cmd_until(p, a):
    target = p.r2p.integer(a[0])
    addr = p.symulate(stop=target, stop_on_sj=True)
    assert(addr==target)
    p.r2p.seek(addr)
    return

# continue until symbolized jump
@pimp.pimpcmd("dcusj")
def cmd_until_symjump(p, a):
    addr = p.symulate(stop_on_sj=True)
    p.last_symjump = addr
    for caddr in p.comments:
        p.r2p.set_comment(p.comments[caddr], caddr)

    p.r2p.seek(addr)


# continue until symbolized instruction
@pimp.pimpcmd("dcusi")
def cmd_until_sym(p, a):
    addr = p.symulate(stop_on_si=True)
    for caddr in p.comments:
        p.r2p.set_comment(p.comments[caddr], caddr)

    p.r2p.seek(addr)

# go to current jump target
@pimp.pimpcmd("take")
def cmd_take_symjump(p, a):
    if p.last_symjump == None:
        print "Can't do that right now"
    addr = p.last_symjump
    inst = p.disassemble_inst(addr)
    if not p.is_conditional(inst):
        print "error: invalid instruction type"
        return
    target = inst.getFirstOperand().getValue()

    cstr = p.build_jmp_constraint(pc=addr)
    if not p.process_constraint(cstr):
        print "error: could not resolve constraint"
        return

    # reset and execute intil target is reached
    p.reset()
    times = 0
    for inst in p.inst_iter():
        if  inst.getAddress() == p.last_symjump and p.trace[p.last_symjump] == times:
            p.trace[p.last_symjump] += 1
        elif inst.getAddress() == p.last_symjump:
            times += 1
            p.process_inst()

        # this works totally by chance...
        if inst.getAddress() == target:
            p.r2p.seek(target)
            p.r2p.set_flag("regs", p.pcreg.getName(), 1, target)
            p.last_symjump = None
            return
    print "error: end of execution"

# avoid current jump target
@pimp.pimpcmd("avoid")
def cmd_avoid_symjump(p, a):
    if p.last_symjump == None:
        print "Can't do that right now"
    addr = p.last_symjump
    inst = p.disassemble_inst(addr)
    if not p.is_conditional(inst):
        print "error: invalid instruction type"
        return
    target = inst.getAddress() + inst.getSize()

    cstr = p.build_jmp_constraint(pc=addr, take=False)
    if not p.process_constraint(cstr):
        print "error: could not resolve constraint"
        return

    # reset and execute intil target is reached
    p.reset()
    times = 0
    for inst in p.inst_iter():
        if inst.getAddress() == target and (p.trace[p.last_symjump] == times):
            p.r2p.seek(target)
            p.r2p.set_flag("regs", p.pcreg.getName(), 1, target)
            p.trace[p.last_symjump] += 1
            p.last_symjump = None
            return
        elif inst.getAddress() == p.last_symjump:
            times += 1
    print "error: end of execution"

# define symbolized memory
@pimp.pimpcmd("input")
def cmd_symbolize(p, a):
    if not len(a):
        for addr in p.inputs:
            b = chr(p.peek(addr, 1))
            if b in string.printable:
                print "{:#x}: {:#x} ({})".format(addr, p.peek(addr, 1), b)
            else:
                print "{:#x}: {:#x}".format(addr, p.peek(addr, 1))
        return
    elif len(a) != 2:
        print "error: command takes either no arguments or 2 arguments"
        return
    size = p.r2p.integer(a[0])
    addr = p.r2p.integer(a[1])

    p.add_input(addr, size)

# sync r2 with input generated by triton
@pimp.pimpcmd("sync")
def cmd_sync_input(p, a):
    for address in p.inputs:
        p.r2p.write_mem(address, get_byte(address))


# reset memory with r2 current state
@pimp.pimpcmd("reset")
def cmd_reset(p, a):
    global cache
    ncache = []
    for m in cache:
        addr = m["start"]
        size = len(m["data"])
        data = p.r2p.read_mem(addr, size)
        p.write_mem(addr, data)
        ncache.append({"start": addr, "data": data})
    cache = ncache

@pimp.pimpcmd("peek")
def cmd_peek(p, a):
    size = p.r2p.integer(a[0])
    addr = p.r2p.integer(a[1])
    print "{:#x}".format(p.peek(addr, size))


@pimp.pimpcmd("poke")
def cmd_poke(p, a):
    value = p.r2p.integer(a[0])
    size = p.r2p.integer(a[1])
    addr = p.r2p.integer(a[2])
    p.poke(addr, size, value)


@pimp.pimpcmd("input_type")
def cmd_input_type(p, a):
    p.input_type = a[0]

success = r2lang.plugin("core", pimp.plugin)
if not success:
    print "[!] Failed loading pimp plugin"
else:
    print "[*] Pimp plugin loaded, available commands are:\n\t{}".format(", ".join(pimp.commands))
