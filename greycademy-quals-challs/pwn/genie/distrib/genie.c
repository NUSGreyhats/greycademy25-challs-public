// Compiled with gcc -fno-toplevel-reorder -o genie genie.c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define PASSWORD_SIZE 16

char password_original[PASSWORD_SIZE] = {1};
char password[PASSWORD_SIZE] = {1};
unsigned char wishes_remaining = 3;

void disable_buffering() {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}


size_t get_choice(char** options, size_t len) {
    size_t choice;
    int result;
    do {
        for(size_t i = 0; i < len; i++) {
            printf("%zu. %s\n", i + 1, options[i]);
        }
        printf("Your choice: (1-%zu): ", len);
        result = scanf("%zu", &choice);
        if (result != 1) {
            while (getchar() != '\n');
            choice = len + 1;
        }
    } while (choice < 1 || choice > len);
    return choice;
}

void randomize_password() {
    int urandom = open("/dev/urandom", O_RDONLY);
    if (urandom < 0) {
        perror("open");
        _exit(1);
    }
    unsigned int seed;
    if (read(urandom, &seed, sizeof(seed)) != sizeof(seed)) {
        perror("read");
        _exit(1);
    }
    close(urandom);
    srand(seed);
    for (size_t i = 0; i < PASSWORD_SIZE; i++) {
        char pchar = 'A' + (rand() % 26);
        password[i] = pchar;
        password_original[i] = pchar;
    }
}



int main() {
    disable_buffering();
    randomize_password();
    puts("Welcome to the Genie Program!");
    char buf[PASSWORD_SIZE];
    unsigned char index;
    while(1){
        printf("You have %u wish%s remaining.\n", wishes_remaining, wishes_remaining == 1 ? "" : "es");
        char* choices[] = {"Make a wish", "Reveal flag", "Quit"};
        size_t choice = get_choice(choices, 3);
        puts("");
        if(choice == 3){
            _exit(0);
        }
        else if(choice == 2){
            printf("Enter password: ");
            read(0, buf, PASSWORD_SIZE);
            if(memcmp(buf, password_original, PASSWORD_SIZE) == 0){
                puts("Access granted! Here is your flag:");
                system("cat flag.txt");
            }
            else{
                puts("Access denied! Incorrect password.");
            }
            _exit(0);
        }
        else if(choice == 1){
            if(wishes_remaining == 0){
                puts("You have no wishes remaining!");
                _exit(0);
            }
            puts("You may choose one of the following wishes:");
            size_t wish_choice = get_choice((char*[]){"Reveal 1 byte of password", "Reveal whole password"}, 2);
            if(wish_choice == 1){
                printf("Enter byte index to reveal (0-%d): ", PASSWORD_SIZE - 1);
                scanf("%hhu", &index);
                printf("password[%d] = '%c'\n", index, password[index]);
                password[index] = '\0';
            }
            else if(wish_choice == 2){
                puts("Haha nope!");
            }
            wishes_remaining--;
        }
        puts("");
    }
    return 0;
}