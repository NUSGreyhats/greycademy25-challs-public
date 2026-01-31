# ==========================================================================================
# README !!!
# helpful resources on this topic (bitwise operations):
#  -  https://www.youtube.com/watch?v=BGeOwlIGRGI recap                                     
#  -  https://www.youtube.com/watch?v=6tNSxabHqRI optional (ignore the NES-specific content)
#  -  https://www.youtube.com/watch?v=ZRNO-ewsNcQ (optional but helpful) common constructs  
# only if you need revision for binary / hex:
#  -  https://www.youtube.com/watch?v=Xpk67YzOn5w binary
#  -  https://www.youtube.com/watch?v=onGJrgJYG2E hexadecimal
# have fun! jump straight to PART I.
# ==========================================================================================


# ===================================================
# answer verification for part 1
# how this works is irrelevant to the challenge.
# you can just think of this as an opaque grader.
# but if you're curious, search up hashing and SHA256
# ===================================================
from hashlib import sha256
def verify(answer):
    return sha256(answer.encode()).hexdigest() == '1ad321bd42eb719930fc02412b70fd0104f019746ce586e7a506bcd494d97fd8'
# ===================================================



# ================================================================================
# PART I
# steps:
#  1. figure out what `mystery` does.
#     hint: you may assume x and y are 1 byte each (256 possible values).
# tips:
#  -  what are these symbols!?!? (& | << >>)
#  -  how does % and ** play a role in this ecosystem?
#  -  if it helps, fix specific values of x and y and try to run through the code.
# ================================================================================

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

print('What does this mystery function do?')
print('Hint: It is a common operation, 3 letters long.')
print('Please answer in all lowercase characters.')
answer = input('>>> ')
if not verify(answer): # you don't have to know how verify() works
    print('Wrong! However, do let us know if you feel your answer should be accepted...')
    exit()

print('Correct!')
print('Please proceed to part 2.')



# ==========================================================================================
# PART II
# steps:
#  1. figure out what `rol` does (should be relatively simple)
#     again, you may assume x has a size of 1 byte (256 possible values).
#  2. understand what the wall of code below does
#  3. compare the different ways of representing numbers. python is quite flexible like that
#      a. what does `.encode()` do?
#  4. think about how to derive each character of the flag
# ==========================================================================================

print('When you\'re ready, enter the flag:')
flag = input('>>> ').encode()
key = b'merry christmas'
check = [40, 139, 226, 176, 128, 74, 139, 141, 176, 177, 68, 142, 35, 66, 65, 100, 22, 2, 99, 142, 69, 17, 115, 24, 8, 194, 178, 3, 160, 60, 30, 0, 0, 75, 5, 40, 16, 56, 46, 99, 7]

def rol(x, n):
    for _ in range(n):
        x = (x << 1 | x >> 7) & 0xff
    return x

# good luck!

assert len(flag) == 41
assert rol(mystery(flag[0], key[0]), 10) == check[0]
assert rol(mystery(flag[1], key[1]), 15) == check[1]
assert rol(mystery(flag[2], key[2]), 53) == check[2]
assert rol(mystery(flag[3], key[3]), 60) == check[3]
assert rol(mystery(flag[4], key[4]), 54) == check[4]
assert rol(mystery(flag[5], key[5]), 35) == check[5]
assert rol(mystery(flag[6], key[6]), 55) == check[6]
assert rol(mystery(flag[7], key[7]), 63) == check[7]
assert rol(mystery(flag[8], key[8]), 36) == check[8]
assert rol(mystery(flag[9], key[9]), 27) == check[9]
assert rol(mystery(flag[10], key[10]), 6) == check[10]
assert rol(mystery(flag[11], key[11]), 23) == check[11]
assert rol(mystery(flag[12], key[12]), 37) == check[12]
assert rol(mystery(flag[13], key[13]), 5) == check[13]
assert rol(mystery(flag[14], key[14]), 21) == check[14]
assert rol(mystery(flag[15], key[0]), 57) == check[15]
assert rol(mystery(flag[16], key[1]), 24) == check[16]
assert rol(mystery(flag[17], key[2]), 16) == check[17]
assert rol(mystery(flag[18], key[3]), 13) == check[18]
assert rol(mystery(flag[19], key[4]), 63) == check[19]
assert rol(mystery(flag[20], key[5]), 40) == check[20]
assert rol(mystery(flag[21], key[6]), 32) == check[21]
assert rol(mystery(flag[22], key[7]), 52) == check[22]
assert rol(mystery(flag[23], key[8]), 2) == check[23]
assert rol(mystery(flag[24], key[9]), 51) == check[24]
assert rol(mystery(flag[25], key[10]), 21) == check[25]
assert rol(mystery(flag[26], key[11]), 20) == check[26]
assert rol(mystery(flag[27], key[12]), 48) == check[27]
assert rol(mystery(flag[28], key[13]), 67) == check[28]
assert rol(mystery(flag[29], key[14]), 1) == check[29]
assert rol(mystery(flag[30], key[0]), 57) == check[30]
assert rol(mystery(flag[31], key[1]), 30) == check[31]
assert rol(mystery(flag[32], key[2]), 50) == check[32]
assert rol(mystery(flag[33], key[3]), 6) == check[33]
assert rol(mystery(flag[34], key[4]), 46) == check[34]
assert rol(mystery(flag[35], key[5]), 21) == check[35]
assert rol(mystery(flag[36], key[6]), 56) == check[36]
assert rol(mystery(flag[37], key[7]), 1) == check[37]
assert rol(mystery(flag[38], key[8]), 57) == check[38]
assert rol(mystery(flag[39], key[9]), 45) == check[39]
assert rol(mystery(flag[40], key[10]), 31) == check[40]
print('Correct!')



# ===========================================================================
# PART III
# unlocked only after part 2.
# DOESN'T REQUIRE ANY FURTHER WORK!!! this part is purely for demonstration.
# OPTIONAL; FOR ENRICHMENT.
# you will understand once you've solved part 2 ;)
# again, how below works is irrelevant to the challenge.
# ===========================================================================
_enc = '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'
from base64 import b64decode
with open('bitwise-iii.py', 'wb') as f:
    _dec = b64decode(_enc.encode())
    f.write(bytes(
        x ^ flag[i % len(flag)] ^ (i % 256)
        for i, x in enumerate(_dec)
    ))
print('Part III unlocked! Check your filesystem.')
