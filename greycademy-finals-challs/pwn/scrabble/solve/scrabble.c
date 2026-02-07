// gcc ./scrabble.c -o ./scrabble
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setup() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void print_menu() {
    printf("\n--- Welcome to my interactive and fun scrabble game! ---\n");
    printf("1. Enter character into board\n");
    printf("2. End game\n");
    printf("Choice: ");
}

void game() {
    char board[15][15];
    int choice, r, c;
    char entered_char;
    while (1) {
        print_menu();
        scanf("%d", &choice);
        getchar();
        switch (choice) {
            case 1:
                printf("Enter row: ");
                scanf("%d", &r);
                getchar();
                printf("Enter column: ");
                scanf("%d", &c);
                getchar();
                printf("Enter character: ");
                scanf("%c", &entered_char);
                getchar();
                board[r][c] = entered_char;
                printf("====Current Board====\n");
                for (int i = 0; i < 15; i++) {
                    printf("-----------------------------\n");
                    printf("|");
                    for (int j = 0; j < 15; j++) {
                        printf("%c", board[i][j]);
                        printf("|");
                    }
                    printf("\n");
                }
                printf("-----------------------------\n");
                break;
            case 2:
                printf("Goodbye!\n");
                return;
            default:
                printf("Invalid option!\n");
        }
    }
}

int main() {
    setup();
    game();
    return 0;
}