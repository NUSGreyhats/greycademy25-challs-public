import random
from string import ascii_lowercase

random.seed(67)
flag = 'grey{puzzle_and_pointer_expert}'
key = ascii_lowercase + '_{}'
sz = len(key)

# example:
# char ***ptr;
# x = *(*(char **)((unsigned long *)(*(char **)((int *)((char *)ptr+24)+8)+32)-1)-27)

signed = lambda x: f'{"+" if x >= 0 else ""}{x}'
types = {
    'char ': 1,
    'unsigned char ': 1,
    'short ': 2,
    'unsigned short ': 2,
    'int ': 4,
    'unsigned int ': 4,
    'long ': 8,
    'unsigned long ': 8,
    'float ': 4,
    'double ': 8,
    'void *': 8,
}
types_keys = list(types.keys())
for i, x in enumerate(flag):
    prev = 0
    s = 'ptr'
    for j in range(4):
        typ, cur = random.choice(types_keys), random.randrange(sz)
        jmp = (cur - prev) * (8 // types[typ])
        s = f'(({typ}*){s}{signed(jmp)})' if j != 2 else f'(*({typ}**){s}{signed(jmp)})'
        prev = cur
    jmp = key.index(x) - prev
    s = f'*(*(char **){s}{signed(jmp)})'
    print(f'    if (inp[{i}] != {s}) return 0;')
