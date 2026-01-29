from pwn import *

p = remote("localhost", 5000)

for i in range(10):
    p.recvuntil(b"/ 10")
    p.recvline()
    expr = p.recvuntil(b"=", drop=True)
    ans = eval(expr)
    print(ans)
    p.sendline(str(ans).encode())

p.interactive()
