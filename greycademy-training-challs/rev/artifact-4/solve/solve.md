# Artifact 4

So, what you're looking at right now is a toy VM (Virtual Machine).

When you think of VMs, generally you would think of stuff like your VMware emulator / Oracle VirtualBox / WSL, where you sort of "nest" operating systems. But it doesn't have to be that complicated!

At the heart, especially in the reverse engineering CTF context, a VM is just a program which pretends to be a machine (hence *virtual* machine). This was heavily hinted during training -- what `artifact-4.py` does is really what we had done when we went through the disassembly line by line.

---

To emulate this running of programs, we will of course need:

1. The memory
2. The instructions, loaded into memory
3. The registers to play around with
4. Knowledge of what each instruction actually does

Of course there are other models to emulate other kinds of programs, but we keep close to what we have learnt so far.

In our Python program:

1. The memory

```python
MEM = [None for _ in range(3000)]
```

Initially empty, but subsequently loaded:

```python
# get user input (the python way)
inp = input("Enter VM input: ")
if len(inp) != 25:
    print('Invalid length!')
    exit()
key = '____aadeghhimnorrstttvy{}'
# load input and key into memory
for i in range(25):
    MEM[1000+i] = inp[i]
    MEM[2000+i] = key[i]
```

We do not have any control of `key`, but we do have full control of `inp`. This is the "variability" introduced into our program (if you give it the same input here, the VM will have the same result every time).

And of course,

2. The instructions, loaded into memory

```python
_code = [
  # ...
]
MEM[:len(_code)] = _code
```

Technically no distinction is needed between the data loaded in and the instructions; this is just for emphasis. We do need to run *some* program, after all.

3. The registers to play around with

```python
REG = {
    'A': 0,
    'B': 0,
    'F': 3000,
    'G': 3000,
    'I': 13,   # instruction pointer (rip)
    'X': 0,
    'Y': 0,
    'ZERO': 0, # guaranteed to not change
}
```

A bunch of mysterious symbols for now. Generally in reverse engineering we are the ones trying to prescibe some meaning to them. Sometimes it may get a little difficult to do so, hence we usually just aim to prescribe however much meaning is needed for us to understand the full picture.

Here we already get a little hint saying that `I` corresponds to `rip`.

4. Knowledge of what each instruction actually does

```python
def execute(op, x=0, y=0, z=0):
    if   op == 0: # push
        REG['F'] -= 1; MEM[REG['F']] = REG[x]
    elif op == 1:
        REG[x] = MEM[REG['F']]; REG['F'] += 1
    elif op == 2:
        REG[x] = REG[y] + z
    elif op == 3:
        REG[x] = MEM[REG[y] + z]
    elif op == 4:   
        MEM[REG[x] + y] = REG[z]
    elif op == 5:
        REG[x] = (REG[y] == REG[z])
    elif op == 6:
        if REG[x] is False:
            print('Wrong!')
            exit()
    elif op == 7:
        print('Correct!')
        exit()
    elif op == 8: # call
        execute(0, 'I')
        execute(2, 'I', 'ZERO', y)
```

Without it, we just have a bunch of information written for nothing. We are interested in how a program uses and manipulates information.

---

With all of these together, there may be too many unknowns to even figure out where to start. In this case I quite heavily hinted during training that this VM roughly follows the Assembly instructions we have learnt so far (with some differences of course), so maybe that would be a good starting point.

Some food for thought. Generally we want *something* out of the program, otherwise it is of no interest to us. In this case the "code runner" quite literally only runs the code:

```python
# have fun with the checker!
def run():
    while True:
        instruction = MEM[REG['I']]
        REG['I'] += 1
        execute(*instruction)
```

The "outcomes of interest" actually lie directly in the list of opcodes:

```python
    elif op == 6:
        if REG[x] is False:
            print('Wrong!')
            exit()
    elif op == 7:
        print('Correct!')
        exit()
```

Quite clearly we simply want to eventually reach the instruction with opcode `7`, while making sure everytime `6` is reached, `REG[x]` is `True`. Whatever the latter clause means (just keeping it at the back of our head for now). A brief scroll-through of the code shows us some form of reasonable behaviour at the bottom:

```python
    # ...
    (2, 'X', 'X', 1),
    (2, 'Y', 'ZERO', 24),
    (8, 0),
    (6, 'A'),
    (7,)
]
```

In general it just looks like there are a lot of "guard checks" (`6`) on register `A`, and only when all checks have passed will we reach `7`. **Just one possibility,** but always work with some starting point. Assumptions can always be refined as we uncover more of the program.

But where exactly is `A` even touched? Our "main" basically has no mentions of `A` aside from being checked by `6`. If the other instructions don't *implicitly* modify `A`, that wouldn't make sense as all the checks will either *all pass* or *all fail*. So maybe we need to examine the other opcodes in more detail.

---

Again we focus on one small section. If unsure where to start, just start near the top.

```python
    (2, 'X', 'ZERO'),
    (2, 'Y', 'ZERO', 8),
    (8, 0), # points to the start of this list
    (6, 'A'),
    (2, 'X', 'X', 1),
    (2, 'Y', 'ZERO', 15),
    (8, 0),
    (6, 'A'),
```

It's actually quite obvious that there is some repetitve pattern going on. "main" basically *only* executes `2`, `6` and `8`. Let's start wtih `2`:

```python
def execute(op, x=0, y=0, z=0):
    # ...
    elif op == 2:
        REG[x] = REG[y] + z
```

I don't know about you, but this reminds me of a `mov` instruction. Especially corresponding to the first line of code

```python
    (2, 'X', 'ZERO'),
```

This *moves* the value in register `ZERO` to register `X` (since `z=0` implicitly). `ZERO` is very conveniently named and with the commented hint it just means it is used as a "zero register" (convenience feature so that the machine can have an easy way to get a `0`). This line just means `mov X, 0`.

What about the next one?

```python
    (2, 'Y', 'ZERO', 8),
```

Quite similar to the previous one, but this time `z=8`. Hence we have `REG['Y'] = REG['ZERO'] + 8`, or `mov Y, 8`.

---

Next:

```python
    (8, 0), # points to the start of this list
```

New opcode.

```python
    if   op == 0: # push
        REG['F'] -= 1; MEM[REG['F']] = REG[x]
    # ...
    elif op == 8: # call
        execute(0, 'I')
        execute(2, 'I', 'ZERO', y)
```

A bunch of "recursive searching" going on, but luckily the hint provided cuts some of our troubles.

If you really want to work it out what `0` does, what I would do is to try to compare a "before and after" or some arbitrary program state:

(before)

```
F = 1234
x is register A; A = 99999
MEM:
      ....
     [1230]
     [1231]
     [1232]
     [1233]
F -> [1234]
      ....
```

(after)

```
F = 1233
x is register A; A = 99999
MEM:
      ....
     [1230]
     [1231]
     [1232]
F -> [1233] 99999
     [1234]
      ....
```

Then we try to build some intuition for this operation. In short, this is how "pushing values onto the stack" works, and `F` is our stack pointer. Again just a "best guess", but we can always revisit this eventually if needed.

(I did not manage to cover the entire stack section in the slides for some groups, hence this artifact was largely skipped over.)

Going back to our opcode `8`, we are executing 2 "sub-instructions" at the same time: `push I; mov I, y`. Or to concretize things, `push rip, mov rip, 0` (since we are executing with `y=0`). If you have again read up on the stack section, this sort of looks like a `call 0`. Functions! Quite visibly delineated in our code listing, the first chunk of instructions belong to 1 function:

```python
_code = [
    (0, 'G'),
    (2, 'G', 'F'),
    (2, 'F', 'F', -2),
    (3, 'A', 'X', 1000),
    (4, 'G', -1, 'A'),
    (3, 'A', 'Y', 2000),
    (4, 'G', -2, 'A'),
    (3, 'A', 'G', -1),
    (3, 'B', 'G', -2),
    (5, 'A', 'A', 'B'),
    (2, 'F', 'G'),
    (1, 'G'),
    (1, 'I'),

# vm entrypoint (our "main")
# ...
```

---

This is a good time to remind that our current goal is to figure out where exactly `A` is used and modified, and also what it represents to us. Already we can see some references to `A`; we can be impatient and look at the last reference

```python
    (5, 'A', 'A', 'B'),
```

```python
def execute(op, x=0, y=0, z=0):
    # ...
    elif op == 5:
        REG[x] = (REG[y] == REG[z])
```

Ooh, a comparison? More than likely (if the function doesn't do some funny business) this *could be potentially* related to our "guard check" right outside this function. This gives us some idea of what this function *could potentially be* doing.

To skip a bit, the first 3 lines are the function prologue (see relevant section of slides), and the last 3 are the function epilogue (see relevant section of slides). Along the way we do uncover more information about what some of the unknown symbols represent:

- `F` for stack pointer, `G` for base pointer
- Opcode `1` is pop
- Hence the function prologues and epilogues look like

```asm
push rbp
mov  rbp, rsp
sub  rsp, 2
...
mov  rsp, rbp
pop  rbp
ret           ; pop rip
```

This allows us to claim with greater certainty that what we are looking at is a function. We now have to discover what `3` and `4` do, being used in bulk in our function:

```python
def execute(op, x=0, y=0, z=0):
    # ...
    elif op == 3:
        REG[x] = MEM[REG[y] + z]
    elif op == 4:   
        MEM[REG[x] + y] = REG[z]
```

Staring at it for a while (maybe 5 seconds, maybe a good minute, maybe after working out with some concrete scenarios) we come to the conclusion that they sort of "load" and "store" values with respect to the memory. Respectively using x64 as our reference:

```asm
mov  xxx, [yyy+z]    ; 3
mov  [xxx+y], zzz    ; 4
```

Some examples:
```asm
mov  rax, [rbp-8]    ; (3, 'rax', 'rbp', -8)
mov  [rbp-8], rax    ; (4, 'rbp', -8, 'rax)
```

Remembering that `G` is our base pointer (`rbp`), we expand our understanding of the function to this pseudo-assembly:

```asm
push rbp         ;
mov  rbp, rsp    ; function prologue
sub  rsp, 2      ;
mov  A, [X+1000]
mov  [rbp-1], A
mov  A, [Y+2000]
mov  [rbp-2], A
...
mov  rsp, rbp    ;
pop  rbp         ; function epilogue
ret              ;
```

`A` over here is also used as a scratch / general-purpose register. Consistent with x64's calling convention, here we are setting up variables on our stack frame. Notice the `1000` and `2000` -- doesn't that remind you of something?

```python
for i in range(25):
    MEM[1000+i] = inp[i]
    MEM[2000+i] = key[i]
```

Has this clicked yet?

The low `1000`s region holds our input, and the low `2000`s region holds our key.

`X` and `Y`, at least for our first invocation, are quite small indeed. (We also realise that they are probably used as arguments, a la `edi` and `esi`.)

After some processing, we come to the conclusion that we are now already storing `inp[i]` and `key[j]` (for some `i` and `j`) on the stack, as local variables! Quite promising!

The only part left is figuring out how the "variability" of our `inp[i]` eventually "flows" to that of `A` (in the equality). This gap is filled in the last few lines of unexplored code:

```python
    (3, 'A', 'G', -1),
    (3, 'B', 'G', -2),
    (5, 'A', 'A', 'B'),
```

Cut to the chase, we can write our simple decompilation based on what we think is going on:

```c
// X and Y store the arguments
int compare(int i, int j) {
    char var1 = INP[i];  // lines 4-5 (1-indexed)
    char var2 = KEY[j];  // lines 6-7
    return var1 == var2; // lines 8-10
}
// A stores the return value
```

If unconvinced, it is left as an exercise to convince yourself of such ;)

With that, we have completely understood `compare`. We tuck the details away in a black box and just look at it through our assigned name `compare`.

---

Finishing up, we very soon notice that the code in main is extremely repetitive. We can identify chunks of roughly similar content, e.g.

```python
    # ...
    (2, 'X', 'X', 1),    # X += 1
    (2, 'Y', 'ZERO', 7), # Y = 7
    (8, 0),              # A = compare(X, Y)
    (6, 'A'),            # assert_true(A)
    # ...
```

Python pseudocode for this chunk, including the details of `compare`:

```python
idx += 1
assert INP[idx] == KEY[7]
```

The only variation in the structure across the chunks is the constant for `Y`. In fact, `X` always increments linearly, so we could probably guess that it is used as an iteration variable. Or we could just dump them all in a wall:

```python
assert INP[0] == KEY[8]
assert INP[1] == KEY[15]
assert INP[2] == KEY[7]
assert INP[3] == KEY[22]
assert INP[4] == KEY[23]
assert INP[5] == KEY[21]
assert INP[6] == KEY[12]
assert INP[7] == KEY[0]
assert INP[8] == KEY[11]
assert INP[9] == KEY[17]
assert INP[10] == KEY[1]
assert INP[11] == KEY[13]
assert INP[12] == KEY[14]
assert INP[13] == KEY[18]
assert INP[14] == KEY[2]
assert INP[15] == KEY[19]
assert INP[16] == KEY[9]
assert INP[17] == KEY[4]
assert INP[18] == KEY[20]
assert INP[19] == KEY[3]
assert INP[20] == KEY[10]
assert INP[21] == KEY[5]
assert INP[22] == KEY[16]
assert INP[23] == KEY[6]
assert INP[24] == KEY[24]
correct()
```

Hence reversing this is as simple as

```python
KEY = '____aadeghhimnorrstttvy{}'
FLAG = ''.join([KEY[8], KEY[15], KEY[7], KEY[22], KEY[23], KEY[21], KEY[12], KEY[0], KEY[11], KEY[17], KEY[1], KEY[13], KEY[14], KEY[18], KEY[2], KEY[19], KEY[9], KEY[4], KEY[20], KEY[3], KEY[10], KEY[5], KEY[16], KEY[6], KEY[24]])
print(FLAG)
```

```
grey{vm_is_not_that_hard}
```
