from random import randint

def generate_instructions():
    correct_flag = 'grey{one_tw0_thr33_f0ur_f1ve_s1x_s3ven}'
    xor_key, add_key, sub_key = 0x42, 0x4, 0x7
    expected = []    
    for i in range(len(correct_flag)):
        if i % 3 == 0:
            expected.append(ord(correct_flag[i]) ^ xor_key)
        elif i % 3 == 1:
            expected.append(ord(correct_flag[i]) + add_key)
        else:
            expected.append(ord(correct_flag[i]) - sub_key)

    instructions = []    
    for i in range(len(correct_flag)):
        instructions.append(f'input {i}')
        
        if i % 3 == 0:
            instructions.append(f'push {xor_key}')
            instructions.append('xor')
        elif i % 3 == 1:
            instructions.append(f'push {add_key}')
            instructions.append('add')
        else:
            instructions.append(f'push {sub_key}')
            instructions.append('sub')
        
        instructions.append(f'push {expected[i]}')
        instructions.append('equal')
        
        # insert random junk instructions
        for i in range(randint(0, 5)):
            instructions.append(f'push {randint(0, 100)}')
            instructions.append(f'push {randint(0, 100)}')
            instructions.append('add')
            
        for i in range(randint(0, 5)):
            instructions.append(f'push {randint(0, 100)}')
            instructions.append(f'push {randint(0, 100)}')
            instructions.append('sub')
            
        for i in range(randint(0, 5)):
            instructions.append(f'push {randint(0, 100)}')
            instructions.append(f'push {randint(0, 100)}')
            instructions.append('xor')
    
    # insert nop instructions
    nop_count = len(instructions) // 2
    for _ in range(nop_count):
        idx = randint(0, len(instructions))
        instructions.insert(idx, 'swapswap')
    
    return '\n'.join(instructions)


instructions = generate_instructions()
with open('../distrib/instructions_revenge.txt', 'w') as f:
    f.write(instructions)
