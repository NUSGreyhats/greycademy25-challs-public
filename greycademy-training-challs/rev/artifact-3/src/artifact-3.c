// gcc -Wno-implicit-function-declaration -s -o artifact-3.elf artifact-3.c
#include <stdio.h>
#include <string.h>

#define SIZE 20
#define CHECK "dobvxob^i\\obsbo+$\"\x1b."
// grey{real_reversing}
char *KEY = "HELLO";

void dummy(size_t *tmp) {}
int FAKE = 1;

void scramble_input(size_t addr) {
    for (int i = 0; i < (SIZE-5); i++) {
        size_t tmp = addr/FAKE + i;
        dummy(&tmp);
        *(char *)tmp -= 3;
    }
    char *buf = (char *)addr;
    buf[SIZE-5] -= KEY[0];
    buf[SIZE-4] -= KEY[1];
    buf[SIZE-3] -= KEY[2];
    buf[SIZE-2] -= KEY[3];
    buf[SIZE-1] -= KEY[4];
}

int main(void) {
    char buf[SIZE*2];
    printf("Enter the flag: ");
    gets(buf);
    if (strlen(buf) != SIZE) {
        puts("Wrong length!");
        return 0;
    }
    scramble_input((size_t)buf);
    if (!strcmp(buf, CHECK)) {
        puts("Correct!");
        return 0;
    }
    puts("Wrong flag!");
    return 0;
}
