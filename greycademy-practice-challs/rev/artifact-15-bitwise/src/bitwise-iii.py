# ========================================
# PART III (UNLOCKED)
# exploration of a brute-force solution :)
# steps:
#  1. read the code and comments
#  2. run this script
# ========================================

# our functions (directly imported over)
def mystery(x, y):
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
            return res
def rol(x, n):
    for _ in range(n):
        x = (x << 1 | x >> 7) & 0xff
    return x

# our data
key = b'merry christmas'
check = [40, 139, 226, 176, 128, 74, 139, 141, 176, 177, 68, 142, 35, 66, 65, 100, 22, 2, 99, 142, 69, 17, 115, 24, 8, 194, 178, 3, 160, 60, 30, 0, 0, 75, 5, 40, 16, 56, 46, 99, 7]
# let me gather the hardcoded numbers in the text wall.
# in practice you can do this via some simple scripting.
# (of even manually if you feel like)
offsets = [10, 15, 53, 60, 54, 35, 55, 63, 36, 27, 6, 23, 37, 5, 21, 57, 24, 16, 13, 63, 40, 32, 52, 2, 51, 21, 20, 48, 67, 1, 57, 30, 50, 6, 46, 21, 56, 1, 57, 45, 31] 

# let me show you a brute force method!

flag = []
flag_sz = len(check)
for i in range(flag_sz):
    # notice that each character in the flag is INDEPENDENTLY checked.
    # remember 1 byte can only have 256 possible values;
    # have you thought about simply trying every possible value?
    for candidate in range(256):
        # emulate the check from the text wall
        if rol(mystery(candidate, key[i%15]), offsets[i]) == check[i]:
            print(chr(candidate), end='')
            # sometimes it might be the case that there are multiple
            # possible values that pass the check.
            # in this case however i am lazy to deal with that
            # (i personally know only 1 possible value is correct, due to invertibility and stuff.)
            break
# and we're done!
print()
