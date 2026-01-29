// gcc ./chall.c -no-pie -fno-stack-protector -o chall

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setup() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
}

void win() {
    system("cat flag.txt");
}

int main() {
    setup();
    char buf[8];
    printf("Enter input: ");
    gets(buf);
}