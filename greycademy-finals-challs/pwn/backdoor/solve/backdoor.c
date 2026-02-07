// gcc ./backdoor.c -no-pie -o ./backdoor
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setup() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void backdoor() {
    printf("Backdoor activated!\n");
    system("/bin/sh");
}

void no_backdoor() {
    printf("No backdoor activated.\n");
    exit(0);
}

struct Data {
    char buf[0x20];
    void (*func_ptr)();
};

int main() {
    struct Data d;
    d.func_ptr = no_backdoor;
    setup();
    scanf("%35s", d.buf);
    d.func_ptr();
    return 0;
}