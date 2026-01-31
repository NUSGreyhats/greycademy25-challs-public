from pwn import xor

initial = b'\xe6\x17,\x86\x86w\xd8\x11\x02\x1d\xf5\x9dz\x0e\xe4\xca\xc5\xd8\xda\xcc\x12' # from source
final = b'grey{cr4ck3d_1t_0p3n}'
assert len(initial) == len(final)
print(list(xor(initial, final)))
