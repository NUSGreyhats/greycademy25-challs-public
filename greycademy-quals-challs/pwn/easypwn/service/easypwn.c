// gcc ./easypwn.c -no-pie -o ./easypwn
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setup() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void win() {
    system("/bin/sh");
}

void print_menu() {
    printf("\n==== easypwn ====\n");
    printf("1. Enter input\n");
    printf("2. Exit\n");
    printf("Choice: ");
}

void sorcery() {
    char sorcery_buffer[100];
    int chars_read = read(0, sorcery_buffer, 0x100);
    printf("Current sorcery: ");
    write(1, sorcery_buffer, chars_read + 1);
    printf("\n");
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
                sorcery();
            case 2:
                printf("Goodbye!\n");
                break;
            default:
                printf("Invalid option!\n");
        }
    }
    
    return 0;
}