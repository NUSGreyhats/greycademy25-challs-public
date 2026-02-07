import sys


class VirtualMachine:
    def __init__(self, instructions: list[str], memory: list[int]):
        self.instructions = [None] + instructions
        self.pc = 1
        self.six = 6
        self.seven = 7
        self.memory = memory

    def parse_value(self, value: str) -> int:
        if value in ["6", "7"]:
            return int(value)
        return getattr(self, value)
    
    def run(self):
        while self.pc < len(self.instructions):
            inst = self.instructions[self.pc]
            if inst[0] == "#":
                self.pc += 1
                continue
            parts = [part.strip(",") for part in inst.split()]
            opcode = parts[0]

            if opcode == "LOAD":
                setattr(self, parts[1], self.memory[self.parse_value(parts[2])])
            elif opcode == "STORE":
                self.memory[self.parse_value(parts[1])] = self.parse_value(parts[2])
            elif opcode == "MOV":
                val = self.parse_value(parts[2])
                setattr(self, parts[1], val)
            elif opcode == "ADD":
                reg1 = self.parse_value(parts[1])
                reg2 = self.parse_value(parts[2])
                setattr(self, parts[1], (reg1 + reg2))
            elif opcode == "SUB":
                reg1 = self.parse_value(parts[1])
                reg2 = self.parse_value(parts[2])
                setattr(self, parts[1], (reg1 - reg2)&0xff)
            elif opcode == "MUL":
                reg1 = self.parse_value(parts[1])
                reg2 = self.parse_value(parts[2])
                setattr(self, parts[1], (reg1 * reg2))
            elif opcode == "XOR":
                reg1 = self.parse_value(parts[1])
                reg2 = self.parse_value(parts[2])
                setattr(self, parts[1], (reg1 ^ reg2)&0xff)
            elif opcode == "MOD":
                reg1 = self.parse_value(parts[1])
                reg2 = self.parse_value(parts[2])
                setattr(self, parts[1], (reg1 % reg2)&0xff)
            elif opcode == "READC":
                addr = self.parse_value(parts[1])
                char = "\n"
                while char == "\n":
                    char = sys.stdin.read(1)
                self.memory[addr] = ord(char)
            elif opcode == "PUTS":
                addr = self.parse_value(parts[1])
                while self.memory[addr] != 0:
                    sys.stdout.write(chr(self.memory[addr]))
                    addr += 1
                sys.stdout.flush()
            elif opcode == "JNZ":
                if self.six != self.seven:
                    addr = int(parts[1])
                    self.pc = addr
                    insn = self.instructions[self.pc]
                    assert insn.startswith("# JUMP TARGET "), f"Invalid jump target at line {self.pc}: {insn}"
                    continue
            elif opcode == "HALT":
                break

            self.pc += 1

insns = open("./67.txt").read().strip().split("\n")
memory = [0] * 0x6767

def write_string(s: str, addr: int):
    for i, c in enumerate(s):
        memory[addr + i] = ord(c)
    memory[addr + len(s)] = 0

write_string("Flag: ", 7*7*7)
write_string("Nope!\n", 7*7*7 + 7)
write_string("Correct!\n", 7*7*7 + 14)
write_string("T\xf7\xac\x0f\x83Q\x97\xc5#\xb7]\xaf\xb2\xefwe,\x17GDU\xacW\t\xc5\xca:\xd5R\x0b\r\xa5\xc7[\x07\xa3\x15\xe2!\r\x8cE\xdd\x0f\x0fq\xfc\xdf\xac\xad\xfd\xc4\xcf\x07\xf7\xbfiw\x9dY\xfc\x91\x9c\x02l\xf6\x8c", 7*7 + 67)

vm = VirtualMachine(insns, memory)
vm.run()