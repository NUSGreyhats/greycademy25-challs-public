// gcc ./milk_tea.c -no-pie -fno-stack-protector -o ./milk_tea
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setup() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void pop_rdi() {
    __asm__(
        "pop %rdi ; ret"
    );
}

char order[0x100];

int main() {
    setup();
    printf("Enter your milk tea order: ");
    read(0, order, 0x100 - 1);
    char feedback[40];
    printf("Your order has been prepared!\n");
    printf("Do you have any feedback for us?\n");
    printf("Feedback > ");
    read(0, feedback, 0x40);
    printf("Thank you and see you soon!\n");
    return 0;
}