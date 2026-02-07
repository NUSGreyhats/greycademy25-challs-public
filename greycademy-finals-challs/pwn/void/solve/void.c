// gcc ./void.c -no-pie -fno-stack-protector -static -o ./void
#include <linux/seccomp.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>

void setup() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main() {
    setup();
    char buf[16];
    int flag = open("flag.txt", O_RDONLY);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
    gets(buf);
    return 0;   
}