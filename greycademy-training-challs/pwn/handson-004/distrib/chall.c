// gcc ./chall.c -no-pie -fno-stack-protector -o chall

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setup() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
}

int main() {
    setup();
    char buf[8];
    printf("Here's a libc leak for you: %p\n", printf);
    printf("Enter input: ");
    gets(buf);
}