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

            if opcode == "Six":
                setattr(self, parts[1], self.memory[self.parse_value(parts[2])])
            elif opcode == "Seven":
                self.memory[self.parse_value(parts[1])] = self.parse_value(parts[2])
            elif opcode == "sIx":
                val = self.parse_value(parts[2])
                setattr(self, parts[1], val)
            elif opcode == "sEven":
                reg1 = self.parse_value(parts[1])
                reg2 = self.parse_value(parts[2])
                setattr(self, parts[1], (reg1 + reg2))
            elif opcode == "siX":
                reg1 = self.parse_value(parts[1])
                reg2 = self.parse_value(parts[2])
                setattr(self, parts[1], (reg1 - reg2)&0xff)
            elif opcode == "seVen":
                reg1 = self.parse_value(parts[1])
                reg2 = self.parse_value(parts[2])
                setattr(self, parts[1], (reg1 * reg2))
            elif opcode == "sevEn":
                reg1 = self.parse_value(parts[1])
                reg2 = self.parse_value(parts[2])
                setattr(self, parts[1], (reg1 ^ reg2)&0xff)
            elif opcode == "SIx":
                reg1 = self.parse_value(parts[1])
                reg2 = self.parse_value(parts[2])
                setattr(self, parts[1], (reg1 % reg2)&0xff)
            elif opcode == "SIX":
                addr = self.parse_value(parts[1])
                char = "\n"
                while char == "\n":
                    char = sys.stdin.read(1)
                self.memory[addr] = ord(char)
            elif opcode == "seveN":
                addr = self.parse_value(parts[1])
                while self.memory[addr] != 0:
                    sys.stdout.write(chr(self.memory[addr]))
                    addr += 1
                sys.stdout.flush()
            elif opcode == "SEven":
                if self.six != self.seven:
                    addr = int(parts[1])
                    self.pc = addr
                    insn = self.instructions[self.pc]
                    assert insn.startswith("# JUMP TARGET "), f"Invalid jump target at line {self.pc}: {insn}"
                    continue
            elif opcode == "sevEN":
                break
            else:
                raise ValueError(f"Unknown opcode: {opcode}")

            self.pc += 1

insns = """
siX seven 6
Seven 6 seven
siX six seven
sEven six six
Seven 7 six
sIx seven, 6
seVen six seven
sEven six 7
sIx seven 6
sEven seven 6
Seven seven six
Six seven 6
siX six seven
Six seven 7
sEven six seven
sIx seven 7
sEven seven 6
Seven seven six
Six seven 7
sEven six seven
sIx seven 7
sEven seven 7
Seven seven six
sIx seven 7
seVen seven 7
seVen seven 7
seveN seven
sIx six 7
seVen six six
sIx seven 6
sEven seven 6
Six seven seven
sEven seven six
Seven 7 seven
sIx six 7
seVen six six
# JUMP TARGET 0
SIX six
Six seven 6
sEven six seven
Six seven 7
# Loop (JUMP TARGET 0)
SEven 37
sIx six 7
seVen six six
Seven 6 six
sIx six 7
sEven six 6
sIx seven 7
siX seven 6
Seven seven six
Six six 7
sIx seven 6
sEven seven seven
Six seven seven
sEven six seven
sIx seven 7
siX seven seven
Seven seven six
# JUMP TARGET 1
sIx seven 7
sEven seven 6
Six six seven
sIx seven 6
sEven seven 6
Six seven seven
seVen six seven
sIx seven 7
sEven seven 7
Six seven seven
sEven six seven
sIx seven 7
sEven seven 6
Seven seven six
sIx seven 7
siX seven 6
Six seven seven
Six six 6
sEven six seven
Six six six
sIx seven 7
sEven seven 6
Six seven seven
sevEn six seven
Six seven 7
Six seven seven
# Jump to Jump target 2
SEven 119
sIx seven 7
siX seven 6
Six six seven
sIx seven 7
sEven seven 6
seVen six seven
sIx seven 6
sEven seven seven
Six seven seven
SIx six seven
sIx seven 7
siX seven 6
Seven seven six
Six six 7
sIx seven 7
siX seven 6
sEven six seven
Seven 7 six
sIx seven 7
siX seven seven
Six seven seven
# Jump to jump target 1
SEven 60
sIx six 7
seVen six six
seVen six 7
sEven six 7
sEven six 7
seveN six
sevEN
# JUMP TARGET 2
sIx six 7
seVen six six
seVen six 7
sEven six 7
seveN six
sevEN
"""

insns = insns.strip().split("\n")
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