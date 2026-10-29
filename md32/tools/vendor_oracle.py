#!/usr/bin/env python3
"""Run the vendor disassembler's x86-64 code under Unicorn, on any host.

Optional verification tool: pip install unicorn. See doc/research.md for the
public objdump download and checksum. This does not execute the vendor program
as a host process; only its disassembly function and operand helpers run.
"""
import json
import re
import struct
import subprocess
from extract_opcodes import Elf
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSI,
                              UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8,
                              UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP)


class Oracle:
    def __init__(self, path):
        self.elf = Elf(path)
        self.uc = u = Uc(UC_ARCH_X86, UC_MODE_64)
        u.mem_map(0, 0x1000)
        u.mem_map(0x400000, 0x300000)
        u.mem_map(0x1000000, 0x20000)
        data = self.elf.data
        phoff = struct.unpack_from('<Q', data, 32)[0]
        entsize, count = struct.unpack_from('<HH', data, 54)
        for i in range(count):
            typ, flags, off, va, pa, filesz, memsz, align = struct.unpack_from(
                '<IIQQQQQQ', data, phoff + i * entsize)
            if typ == 1:
                u.mem_write(va, data[off:off + filesz])
        self.out = []
        self.code = b''
        self.base = 0
        self.hooks = []
        self.hook(0x1000000, self.printf)
        self.hook(0x1000010, self.read_memory)
        self.hook(0x1000020, self.address)
        self.hook(0x1000030, lambda: self.ret(0))
        self.info = 0x1001000
        u.mem_write(self.info, bytes(256))
        for off, addr in [(0, 0x1000000), (0x70, 0x1000010), (0x78, 0x1000030),
                          (0x80, 0x1000020)]:
            u.mem_write(self.info + off, struct.pack('<Q', addr))
        self.hook(self.elf.symbols['xmalloc'][0], lambda: self.ret(0x1002000))
        imports = json.loads(subprocess.check_output(
            ['r2', '-N', '-q', '-c', 'iij', str(path)], stderr=subprocess.DEVNULL))
        callbacks = {'free': lambda: self.ret(0), 'strcmp': self.strcmp,
                     '__stack_chk_fail': self.fail}
        for imp in imports:
            if imp['name'] in callbacks:
                self.hook(imp['plt'], callbacks[imp['name']])
        # Do not depend on the vendor default ISA selection.
        u.mem_write(self.elf.symbols['md32_isa_index'][0], struct.pack('<I', 0))

    def hook(self, address, fn):
        self.hooks.append(self.uc.hook_add(UC_HOOK_CODE, lambda u, a, s, _: fn(),
                                          begin=address, end=address))

    def reg(self, reg):
        return self.uc.reg_read(reg)

    def string(self, addr):
        out = bytearray()
        while True:
            ch = self.uc.mem_read(addr + len(out), 1)
            if ch == b'\0':
                return out.decode()
            out += ch

    def ret(self, value=0):
        sp = self.reg(UC_X86_REG_RSP)
        dest = struct.unpack('<Q', self.uc.mem_read(sp, 8))[0]
        self.uc.reg_write(UC_X86_REG_RAX, value & ((1 << 64) - 1))
        self.uc.reg_write(UC_X86_REG_RSP, sp + 8)
        self.uc.reg_write(UC_X86_REG_RIP, dest)

    def strcmp(self):
        a = self.string(self.reg(UC_X86_REG_RDI))
        b = self.string(self.reg(UC_X86_REG_RSI))
        self.ret((a > b) - (a < b))

    def fail(self):
        raise RuntimeError('Vendor stack check failed')

    def printf(self):
        fmt = self.string(self.reg(UC_X86_REG_RSI))
        vals = iter(self.reg(r) for r in [UC_X86_REG_RDX, UC_X86_REG_RCX,
                                        UC_X86_REG_R8, UC_X86_REG_R9])
        def replace(m):
            v = next(vals)
            t = m.group()[-1]
            if t == 's':
                return self.string(v)
            if t in 'di':
                return str(v if v < (1 << 63) else v - (1 << 64))
            if t in 'xX':
                return format(v, t)
            if t == 'u':
                return str(v)
            raise ValueError(m.group())
        self.out.append(re.sub(r'%[-#0-9.*lhz]*[sdixXu]', replace, fmt))
        self.ret(len(self.out[-1]))

    def address(self):
        self.out.append(hex(self.reg(UC_X86_REG_RDI)))
        self.ret()

    def read_memory(self):
        addr = self.reg(UC_X86_REG_RDI) - self.base
        dst = self.reg(UC_X86_REG_RSI)
        size = self.reg(UC_X86_REG_RDX)
        self.uc.mem_write(dst, (self.code[addr:addr + size] + bytes(size))[:size])
        self.ret()

    def call(self, addr, *args):
        sp = 0x101fff0
        self.uc.mem_write(sp, struct.pack('<Q', 0x1000100))
        self.uc.reg_write(UC_X86_REG_RSP, sp)
        for r, v in zip([UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX], args):
            self.uc.reg_write(r, v & ((1 << 64) - 1))
        self.uc.emu_start(addr, 0x1000100, count=100000)
        assert self.reg(UC_X86_REG_RIP) == 0x1000100, 'Emulation did not return'
        return self.reg(UC_X86_REG_RAX)

    def decode(self, code, addr=0):
        self.out = []
        self.code = code
        self.base = addr
        size = self.call(self.elf.symbols['print_insn_md32'][0], addr, self.info)
        return size, ''.join(self.out)

    def operand(self, index, shift, word):
        table = self.elf.symbols['arg_make_table'][0]
        fn, = self.elf.unpack('<Q', table + index * 8)
        arg = 0x1003000
        self.uc.mem_write(arg, bytes(64))
        self.uc.mem_write(arg + 24, struct.pack('<Q', arg + 32))
        self.call(fn, arg, shift, word)
        return struct.unpack('<qi', self.uc.mem_read(arg, 12))


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('objdump')
    p.add_argument('hex')
    args = p.parse_args()
    print(Oracle(args.objdump).decode(bytes.fromhex(args.hex)))
