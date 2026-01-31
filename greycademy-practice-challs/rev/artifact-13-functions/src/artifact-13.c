// gcc -o artifact-13 ../src/artifact-13.c
// gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0

#include <stdio.h>
#include <string.h>

char *gets(char *);
void part_2(void);
char smiley[] = " :)";

int main(void) {
    char buf[20] = "Hello world!";
    int x = 67;
    char y = 'i';

    puts("Welcome!");
    puts("Protip: RUN ME DIRECTLY FIRST, ANALYSE AFTERWARDS!");
    puts("If at any point you're confused about some function, google \"man <function>\".");
    puts("(\"man\" stands for \"manual\")");
    puts("=============================================================================");

    puts("Here's the most basic output function (puts)!");
    puts("It automatically adds a newline at the back.");

    printf("printf doesn't add its own newlines.\nBUT it can format data to output: %s %d\n", buf, x);

    printf("Output by characters: %c", buf[0]);
    putchar(y);

    printf("\ngets is unlimited string input (no points for overflowing): >>> ");
    gets(buf);
    printf("You entered: %s\n", buf);
    printf("Since it is too dangerous, use fgets instead: >>> ");
    fgets(buf, 20, stdin);
    printf("You entered: %s\n", buf);

    puts("scanf automatically formats the input into the target variables.");
    puts("There are a LOT to remember. I personally just have these bookmarked:");
    puts("https://en.wikipedia.org/wiki/Printf#Format_specifier");
    puts("https://en.wikipedia.org/wiki/Scanf#Format_string_specifications");
    printf("Enter a character, a number, and a string, separated by commas: >>> ");
    scanf("%c, %d, %19s", &y, &x, buf);
    printf("You entered: %c, %d, %s\n", y, x, buf);

    puts("Common string functions:");
    printf("Length of string: strlen(buf) = %ld\n", strlen(buf));
    printf("Equality (0 means equal): strcmp(buf, \"Hi\") = %d\n", strcmp(buf, "Hi"));
    strcat(buf, smiley);
    printf("Concatenate: strcat(buf, \" :)\"); buf = %s\n", buf);

    part_2();
    puts("=============================================================================");
    puts("Done!");
    puts("Now, if you've done something funny with the part 1 input earlier,");
    puts("you might see some weird error message later.");
    puts("That's a teaser for binary exploitation! :P");
    return 0;
}

#define PADDING_OFF 0x60
#define NEEDLE_IDX 121
const char padding[0x100-PADDING_OFF] = { 0 };
const struct __attribute__((packed)) {
    char left[NEEDLE_IDX];
    char needle;
    char right[256-NEEDLE_IDX-1];
} haystack = { { 0 }, 127, { 0 } };

// grey{po1ymorphic_memory}
int success = 1;
void part_2(void) {
    char a[7];
    char b[6] = "union";
    long c;
    char d;
    int e;
    float f;
    struct {
        char _unused[3];
        char bof;
        int victim;
    } g;
    g.victim = 1337;
    char *h = (char *)&haystack;
    char i[2];
    puts("=============================================================================");
    puts("Now onto the real deal :)");
    printf("Enter flag: >>> ");
    scanf("%6s%c%ld%c%4c%4c%5c%c%1s", a, &b[0], &c, &d, (char *)&e, (char *)&f, &g.bof, (char *)&h, i);
    if (strcmp(a, "grey{p")) {
        puts("\n                xxxxxx__________________ WRONG!");
        puts("Are you sure you've understood scanf and strcmp?");
        success = 0;
    }
    if (strcmp(b, "onion")) {
        puts("\n                ______x_________________ WRONG!");
        puts("Don't get fooled by the string! Only 1 char is modified!");
        success = 0;
    }
    if (c != 1) {
        puts("\n                _______x________________ WRONG!");
        puts("This is purely a scanf feature.");
        success = 0;
    }
    if ((int)d != 121) {
        puts("\n                ________x_______________ WRONG!");
        puts("Have you pulled up an ASCII chart?");
        success = 0;
    }
    if (e != 0x70726f6d) {
        puts("\n                _________xxxx___________ WRONG!");
        puts("This one might be a bit tricky; read up on little-endian.");
        puts("You'll also need your ASCII chart on this one.");
        success = 0;
    }
    if (f != 16386743068373549056.0f) {
        puts("\n                _____________xxxx_______ WRONG!");
        puts("This is similar to the previous one (e).");
        puts("Do take a look at https://float.exposed");
        success = 0;
    }
    if (g.bof != 'm') {
        puts("\n                _________________x______ WRONG!");
        puts("Should be a giveaway at this point...");
        success = 0;
    }
    if (g.victim != 0x726f6d65) {
        puts("\n                __________________xxxx__ WRONG!");
        puts("Similar to (e). But how do you get to modify this...?");
        puts("Hint: click on the target variable to inspect memory");
        success = 0;
    }
    if (*h != 127) {
        puts("\n                ______________________x_ WRONG!");
        puts("Have you found the needle in the haystack?");
        puts("What are you modifying, and what do you need to modify it to?");
        success = 0;
    }
    if (strcmp(i, "}")) {
        puts("\n                _______________________x WRONG!");
        puts("You could probably guess this character, honestly :)");
        success = 0;
    }
    if (success == 0) {
        return;
    }
    puts("CONGRATULATIONS! You've derived the flag.");
    puts("Hope that was fun :)");
}
