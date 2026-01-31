with open('bitwise-iii.py', 'rb') as f:
    RAW = f.read()

FLAG = b'grey{itsy_bitsy_spider_the_number_master}'

import base64
print(base64.b64encode(bytes(
    x ^ FLAG[i % len(FLAG)] ^ (i % 256)
    for i, x in enumerate(RAW)
)))
