// gcc ./vending-machine.c -no-pie -o ./vending-machine
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

void free_real_estate() {
    __asm__(
        "pop %rdi ; ret"
    );
}

int main() {
    setup();
    double drinks[10];
    for (int i = 0; i < 18; i++) {
        printf("Would you like to continue? (Y/N) > ");
        char resp;
        scanf("%c", &resp);
        getchar();
        if (resp != 'Y') {
            break;
        }
        printf("Enter your drink price > ");
        scanf("%lf", &drinks[i]);
        getchar();

    }
    return 0;   
}