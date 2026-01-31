EXPECTED = [
    6383,2654,6129,1428,5945,1176,5709,1044,5550,1894,5363,1682,5170,1443,5922,1188,5660,949,4358,697,4136,426
]
INITIAL_HASH = 0x1337
flag = ""
prev_hash = INITIAL_HASH
for expected_hash in EXPECTED[::-1]:
    c = (expected_hash ^ 0x1234) - prev_hash
    flag += chr(c)
    prev_hash = expected_hash
print(flag)
