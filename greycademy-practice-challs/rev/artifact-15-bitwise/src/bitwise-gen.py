import random

FLAG = b'grey{itsy_bitsy_spider_the_number_master}'
KEY =  b'merry christmas'

def mystery(x, y):
    assert 0 <= x < 256 and 0 <= y < 256
    res = 0
    i = 0
    while True:
        a = x & 1 << i
        tmp = (y << 1 >> i | 0xdc)
        b = (tmp % 4 & 2) >> 1
        if (a == 0) != (b == 0):
            res += 2 ** i
        i += (tmp & 64) >> 6
        if i >> 2 & 0x9a:
            assert 0 <= res < 256
            return res
for x in range(256):
    for y in range(256):
        assert mystery(x, y) == x ^ y

# will look like: rol(mystery(flag[i], key[i]), off[i]) == check[i]
# key:   bytestring
# off:   hardcoded numbers
# check: indexed numbers

random.seed(67)
OFF = [random.randrange(1, 68) for _ in FLAG]

def rol(x, n):
    for _ in range(n):
        x = (x << 1 | x >> 7) & 0xff
    return x

# assert rol(mystery(flag[0], key[0]), 123) == check[0]
CHECK = [
    rol(mystery(FLAG[i], KEY[i % len(KEY)]), OFF[i])
    for i in range(len(FLAG))
]

print(CHECK)
for i in range(len(FLAG)):
    print(f'assert rol(mystery(flag[{i}], key[{i % len(KEY)}]), {OFF[i]}) == check[{i}]')
