def generate_instructions():
    correct_flag = 'grey{i_l0ve_st4ck_th4_fl3gs!!!}'
    xor_keys = 'ilikewater'
    
    expected = []
    for i, c in enumerate(correct_flag):
        key = ord(xor_keys[i % len(xor_keys)])
        expected.append(ord(c) ^ key)
    
    instructions = []
    
    for i in range(len(correct_flag)):
        key = ord(xor_keys[i % len(xor_keys)])
        instructions.append(f'input {i}')
        instructions.append(f'push {key}')
        instructions.append('xor')
        instructions.append(f'push {expected[i]}')
        instructions.append('equal')
    
    return '\n'.join(instructions)

instructions = generate_instructions()
with open('../distrib/instructions.txt', 'w') as f:
    f.write(instructions)
