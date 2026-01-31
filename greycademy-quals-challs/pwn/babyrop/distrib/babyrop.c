// gcc ./babyrop.c -fno-stack-protector -o ./babyrop
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setup() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void vulnerable_function() {
    char buffer[69];
    
    printf("Enter your input: ");
    gets(buffer);
    
    printf("You entered: %s\n", buffer);
}

void print_menu() {
    printf("\n==== Baby ROP ====\n");
    printf("1. Enter input\n");
    printf("2. Exit\n");
    printf("Choice: ");
}

char* text = "Hackers live in the /bin/sh";

void say_something_cool() {
    printf("My cool text: %p\n", text);
}

void pop_rax() {
    __asm__(
        "pop %rax ; ret"
    );
}

void pop_rdi() {
    __asm__(
        "pop %rdi ; ret"
    );
}

void move_stuff() {
    __asm__(
        "mov %rdi, %rsi ; ret"
    );
}

void lovely_syscalls() {
    __asm__(
        "syscall ; ret"
    );
}

int main() {
    setup();
    
    int choice;
    
    while (1) {
        print_menu();
        scanf("%d", &choice);
        getchar();
        
        switch (choice) {
            case 1:
                vulnerable_function();
                exit(0);
            case 2:
                printf("Goodbye!\n");
                exit(0);
            case 0xdeadbeef:
                say_something_cool();
                break;
            default:
                printf("Invalid option!\n");
        }
    }
    
    return 0;
}