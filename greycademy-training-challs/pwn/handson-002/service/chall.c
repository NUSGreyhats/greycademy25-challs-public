#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setup() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
}

int level() {
  size_t attempt = 0x0;

  __asm__(
    ".intel_syntax noprefix\n"
    "mov r12, 0xc4febabe;"
    ".att_syntax prefix\n"
  );
  puts("What is the value of r12?");
  puts("You'll need to set a breakpoint at one of these puts() calls");
  puts("When the program reaches this instruction, it will pause and allow you to debug in gdb");
  puts("Use 'disass level' to view the disassembly of this function (this function is called level)");
  puts("Use 'break *<addr>' (eg. break *401500) to break at an address");
  puts("pwndbg will show you the current registers by default");
  puts("Use ctx to make pwndbg show the registers again");
  puts("Alternatively, use info reg to view registers");
  puts("Provide your answer in hex (eg. 0xdeadbeef)");
  scanf("%p", &attempt);
  getchar();

  if (attempt != 0xc4febabe) {
    puts("Wrong!");
    exit(-1);
  }

  puts("What is the saved return address at the end of this function?");
  puts("Similarly, set a breakpoint at one of these puts() calls");
  puts("Find the value of RSP, and use x/gx <addr> to view the contents of the stack");
  puts("Locate the saved RIP address (should look something like 0x401500)");
  puts("Provide your answer in hex (eg. 0x401500)");
  scanf("%p", &attempt);
  getchar();

  if (attempt != (&attempt)[0x2]) {
    puts("Wrong!");
    exit(-1);
  }

  return 1;
}

int main() {
  setup();

  if (level()) {
    puts("You win! Here's your shell, cat flag.txt to get the flag.");
    system("/bin/sh");
  }
}
