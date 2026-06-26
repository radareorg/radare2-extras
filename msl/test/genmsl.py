#!/usr/bin/env python3
# Minimal .msl generator mirroring radare2-extras msl/core_msl.c (mslw_*).
# Produces a valid file header + Process Identity + Thread Context + one
# Memory Region + End-of-Capture, with the exact SHA-256 chain + FileHash.
import struct, hashlib, sys

def sha(a, b=b''):
    h = hashlib.sha256()
    if a: h.update(a)
    if b: h.update(b)
    return h.digest()

def pad8(d):
    return d + b'\x00' * ((-len(d)) % 8)

class Dump:
    def __init__(self):
        self.out = b''
        self.fh = hashlib.sha256()   # cumulative FileHash
        self.prev = b''
    def seed(self, filehdr):
        self.out += filehdr
        self.fh.update(filehdr)
        self.prev = sha(filehdr)     # mslw_sha256(fhdr,64,NULL,0)
    def block(self, btype, payload, feed=True):
        padded = pad8(payload)
        hdr = bytearray(80)
        hdr[0:4] = b'MSLC'
        struct.pack_into('<H', hdr, 4, btype)
        struct.pack_into('<I', hdr, 8, 80 + len(padded))
        struct.pack_into('<H', hdr, 12, 1)        # payload version
        # uuid [16:32] left as zeros (random in producer; irrelevant to parsing)
        hdr[48:80] = self.prev
        self.out += bytes(hdr) + padded
        if feed:
            self.fh.update(bytes(hdr)); self.fh.update(padded)
        self.prev = sha(bytes(hdr), padded)

d = Dump()
ARCH_X86_64, OS_LINUX, PID = 1, 1, 1234
cap = (1 << 0) | (1 << 8) | (1 << 2)  # MemoryRegions|ProcessIdentity|ThreadContexts

fhdr = bytearray(64)
fhdr[0:8] = b'MEMSLICE'
fhdr[8] = 1; fhdr[9] = 64
struct.pack_into('<H', fhdr, 10, 0x0101)
struct.pack_into('<Q', fhdr, 16, cap)
struct.pack_into('<Q', fhdr, 40, 0)
struct.pack_into('<H', fhdr, 48, OS_LINUX)
struct.pack_into('<H', fhdr, 50, ARCH_X86_64)
struct.pack_into('<I', fhdr, 52, PID)
fhdr[61] = 0x01  # HashAlgo SHA-256
d.seed(bytes(fhdr))

# Process Identity (0x0040)
exe = b'/tmp/sample\x00'
pi = bytearray(24)
struct.pack_into('<H', pi, 16, len(exe))
pi = bytes(pi) + pad8(exe)
d.block(0x0040, pi)

# Thread Context (0x0011): regs rip (pc), rsp (sp), rax
def reg(name, width, val, flags):
    nm = name.encode() + b'\x00'
    e = bytearray(8)
    e[0] = len(nm); e[1] = width
    struct.pack_into('<H', e, 2, flags)
    return bytes(e) + pad8(nm) + pad8(struct.pack('<Q', val)[:width])

def thread_block(tid, current, rip, rsp, rax):
    regs = reg('rip', 8, rip, 1) + reg('rsp', 8, rsp, 2) + reg('rax', 8, rax, 0)
    tc = bytearray(32)
    struct.pack_into('<Q', tc, 0, tid)             # ThreadID
    struct.pack_into('<H', tc, 16, 1 if current else 0)  # Flags: Current
    tc[18] = 3                                     # ThreadState: Stopped
    struct.pack_into('<I', tc, 20, 3)              # RegCount
    d.block(0x0011, bytes(tc) + regs)

thread_block(7, True, 0x1000, 0x2ff0, 0x2a)
# With --mt, add a second (non-Current) thread parked further into the region,
# to exercise thread listing (dpt) and selection (dpt=<tid>).
if '--mt' in sys.argv:
    thread_block(8, False, 0x1100, 0x2fe0, 0xbb)

# Memory Region (0x0001): base 0x1000, size 0x2000 (2 pages), all captured.
base, size, page = 0x1000, 0x2000, 4096
npages = size // page
psm_bytes = (((npages + 3) // 4) + 7) & ~7   # all zero = all CAPTURED
psm = b'\x00' * psm_bytes
data = bytes(((0x1000 + i) & 0xff) for i in range(size))  # recognizable pattern
mr = bytearray(32)
struct.pack_into('<Q', mr, 0, base)
struct.pack_into('<Q', mr, 8, size)
mr[16] = 1 | 4   # prot: R|X
mr[18] = 12      # PageSizeLog2
d.block(0x0001, bytes(mr) + psm + data)

# End-of-Capture (0x0FFF): FileHash + timestamp, not fed into FileHash.
eoc = bytearray(48)
eoc[0:32] = d.fh.digest()
d.block(0x0FFF, bytes(eoc), feed=False)

outpath = next((a for a in sys.argv[1:] if not a.startswith('-')), None)
if not outpath:
    sys.exit("usage: genmsl.py [--mt] OUTPUT.msl")
open(outpath, 'wb').write(d.out)
print("wrote %s (%d bytes)" % (outpath, len(d.out)))
