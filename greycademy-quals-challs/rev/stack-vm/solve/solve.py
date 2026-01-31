# each 5-line block enforces (input[i] XOR A) == B
# so we can just reverse the XOR operation to get the flag

# input i
# push A
# xor
# push B
# equal

with open("../distrib/instructions.txt") as f:
    instructions = f.readlines()
    for i in range(0, len(instructions), 5):
        
        A = int(instructions[i + 1].strip().split(" ")[1])
        B = int(instructions[i + 3].strip().split(" ")[1])
        input_char = chr(A ^ B)
        print(input_char, end="")
print()
