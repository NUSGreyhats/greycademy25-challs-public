#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setup() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
}

int level1() {
  size_t *ptr = (size_t *)0x404500;
  size_t attempt = 0;

  *ptr = 0xd00df00d;

  puts("What is the value at 0x404500? Use x/gx <addr> to view memory as 64-bit integers.");
  puts("Provide your answer in hex (eg. 0xdeadbeef)");
  scanf("%p", &attempt);
  getchar();

  if (attempt != *ptr) {
    puts("Wrong!");
    exit(-1);
  } else {
    puts("Correct!");
    return 1;
  }
}

void hello() {
  puts("is there something interesting here?");
  __asm__("pop %rdi;");
  puts("goodbye!");
  __asm__("push %rdi;");
}

int level2() {
  char *attempt = malloc(0x20);

  puts("What is the instruction at 0x401399? Use x/i <addr> to view memory as assembly instructions.");
  puts("Provide your answer without a trailing semicolon (eg. push rax)");
  fgets(attempt, 0x20, stdin);
  attempt[strcspn(attempt, "\n")] = 0;

  if (strcmp(attempt, "pop rdi")) {
    puts("Wrong!");
    exit(-1);
  } else {
    puts("Correct!");
    return 1;
  }
}

int level3() {
  struct {
    size_t attempt;
    char a[0x28];
  } stack;

  stack.attempt = 0xdeadbeef;
  memset(stack.a, 'A', 0x28);

  __asm__(
    ".intel_syntax noprefix\n"
    "lea rsi, [rbp+0x10];"
    ".att_syntax prefix\n"
  );

  printf("Given that the end of this function's stack is at address %p, find the address of its start (ie. the address containing 0xdeadbeef)\n");
  puts("--- start of stack ---");
  puts("size_t attempt = 0xdeadbeef;");
  puts("char a[0x28]; // filled with \"A\", 0x41 in hex");
  puts("saved stack address (should look something like 0x7fffffffd700)");
  puts("saved return address (should look something like 0x401500)");

  __asm__(
    ".intel_syntax noprefix\n"
    "lea rsi, [rbp+0x10];"
    ".att_syntax prefix\n"
  );
  printf("--- end of stack (%p points here) ---\n");

  puts("Note: the correct answer will change every time on remote due to ASLR!");
  puts("Once you've found the offset from the given address to the correct answer in gdb, you must use that offset to calculate the address on remote.");
  puts("To find a value in memory, use search -p <value>");
  puts("Once you've found the address, use x/gx to verify that the stack indeed tallies with the layout shown above.");
  puts("Provide your answer in hex (eg. 0x7fffffffd700)");

  scanf("%p", &stack.attempt);
  getchar();

  if (stack.attempt != &stack.attempt) {
    puts("Wrong!");
    exit(-1);
  } else {
    puts("Correct!");
    return 1;
  }
}

int main() {
  setup();

  if (level1() && level2() && level3()) {
    puts("You win! Here's your shell, cat flag.txt to get the flag.");
    system("/bin/sh");
  }
}
