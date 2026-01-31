// gcc -o artifact-11 artifact-11.c
// gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char wizard_art_for_fun[] = "\n                  .\n\n                   .\n         /^\\     .\n    /\\   \"V\"\n   /__\\   I      O  o\n  //..\\\\  I     .\n  \\].`[/  I\n  /l\\/j\\  (]    .  O\n /. ~~ ,\\/I          .\n \\\\L__j^\\/I       o\n  \\/--v}  I     o   .\n  |    |  I   _________\n  |    |  I c(`       ')o\n  |    l  I   \\.     ,/\n_/j  L l\\_!  _//^---^\\\\_    -Row\n\n";
const unsigned char KEY[] = { 129, 101, 73, 255, 253, 20, 170, 37, 97, 118, 198, 249, 37, 63, 144, 149, 245, 168, 233, 162, 111 };

void give_introduction(void) {
    puts("How familiar are you with reading C code?");
    puts("We shall find out...");
    puts("Some tips: Don't worry if you don't understand every detail!");
    puts("Analyse what you need. I've left the function names in the decompilation (through magic).");
    puts("");
}

char *ask_for_string_input(void) {
    char *buf = malloc((size_t)33);
    printf("Enter some text (max 32 characters): >>> ");
    scanf("%32[^\n]", buf);
    printf("You entered: %s\n", buf);
    return buf;
}

void change_first_character(char *input) {
    puts("==================================================");
    puts("We shall change the first character of your input!");
    if (strlen(input) == 0) {
        puts("Nothing to change :(");
        return;
    }
    printf("%c >>> ", input[0]);
    input[0] -= 0x20;
    printf("%c\n", input[0]);
}

void change_last_character(char *input) {
    puts("==================================================");
    puts("We shall change the last character of your input!");
    if (strlen(input) == 0) {
        puts("Nothing to change :(");
        return;
    }
    size_t last_idx = strlen(input)-1;
    printf("%c >>> ", input[last_idx]);
    input[last_idx] -= 16;
    printf("%c\n", input[last_idx]);
}

char *add_new_characters(char *input) {
    puts("==================================================");
    puts("Now we shall append new characters to your input!");
    puts("(Optional) For the brave, you can try to decipher my inner workings... >:)");
    char *buf = malloc((size_t)(33+7));
    if (!buf) {
        puts("ruh oh...");
        free(input);
        exit(1);
    }
    strcpy(buf, input);
    strcat(buf, "emy! <3");
    printf("%s >>> %s\n", input, buf);
    free(input);
    return buf;
}

int suspicious_check(char *input) {
    puts("==================================================");
    puts("Let's see if you've gotten the memo...");
    puts(wizard_art_for_fun);
    return !strcmp(input, "I love greycademy! <3");
}

void correct(char *input) {
    puts("Correct! You shall get the flag now.");
    puts("If you are viewing this in IDA, please don't bother reversing me, it's not needed >:)");
    puts("(Unless you are confident and want some challenge)");
    srand(67);
    for (int i = 0; i < 21; i++) {
        input[i] = (char)(
            (unsigned char)input[i] ^ (unsigned char)input[i+1] ^ (unsigned char)(rand() % 256) ^ KEY[i]
        );
    }
    printf("Here's your flag: %s\n", input);
    puts("Hope you had fun! :)");
}

void wrong() {
    puts("You did not get the memo :( shall we try again?");
    puts("Hint: If you see nothing / � displayed after changing the first / last character,");
    puts("    e.g. something like");
    puts("");
    puts("A >>> ");
    puts("or");
    puts("A >>> �");
    puts("");
    puts("Consider trying a different character that might get it to work :P");
    puts("In this case, perhaps further down the ASCII chart (but why? that's for you to figure out).");
    puts("Goodbye!");
}

void you_can_ignore_this_just_a_cleanup(char *input) {
    free(input);
}

int main(void) {
    give_introduction();
    char *input = ask_for_string_input();
    change_first_character(input);
    change_last_character(input);
    input = add_new_characters(input);
    if (suspicious_check(input)) {
        correct(input);
    } else {
        wrong(input);
    }
    you_can_ignore_this_just_a_cleanup(input);
    return 0;
}
