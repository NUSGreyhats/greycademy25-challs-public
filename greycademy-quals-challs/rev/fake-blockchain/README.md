# fake-blockchain

# Description
How do I make all the blocks valid???

# Solution

1. Each node in the linked list has this structure 
```c
typedef struct Block {
    char data;
    unsigned int hash;
    struct Block* prev;
} Block;
```
2. The expected hashes are stored in the global variable and all the blocks will be validated when we view.
3. The hash of the latest block is derived from the hash of the current block. Retrieve the characters in reversed order starting with the initial hash `0x1337`

# Flag

`grey{struct5_4re_ug1y}`

# Author

onetw0three
