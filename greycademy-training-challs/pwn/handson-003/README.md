# Details

ret2win by overwriting the saved RIP value with the address of the `win` function to read the flag. If you encounter a segmentation fault at a `movaps` instruction, try overwriting with a `ret` instruction followed by the address of the `win` function to align the stack!

# Author

elijah5399

# Flag

`flag{mum_i_pwned_something!!!}`
