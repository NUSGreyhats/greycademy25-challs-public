# 1. instructions btwn equal[i] & input[i+1] does nothing meaningful, so we can remove that
# 2. swapswap is just nop so we can filter that out too
# 3. now we have only meaningful instructions left, we can extract A and B from each block

# input i
# push A
# add/sub/xor
# push B (expected char)
# equal

with open("../distrib/instructions_revenge.txt") as f:
    
    # filter out redundant instructions
    insns = f.readlines()
    filtered_insns = []
    
    collect = False
    for insn in insns:
        if "input" in insn:
            collect = True
        if collect and "swapswap" not in insn:
            filtered_insns.append(insn)
        if "equal" in insn:
            collect = False

    # reverse operations to get flag
    flag = ""
    for i in range(0, len(filtered_insns), 5):
        A = int(filtered_insns[i + 1].strip().split(" ")[1])
        B = int(filtered_insns[i + 3].strip().split(" ")[1])
        opcode = filtered_insns[i + 2].strip()

        if opcode == "xor":
            flag += chr(A ^ B)
        elif opcode == "add":
            flag += chr(B - A)
        elif opcode == "sub":
            flag += chr(B + A)
    print(flag)
