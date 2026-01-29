// gcc -s -o artifact-1.elf artifact-1.c
// gcc (Debian 15.2.0-9) 15.2.0
#include <stdio.h>

int get_inp(void) {
    int result;
    printf("Enter your guess: ");
    scanf("%d", &result);
    return result;
}

int get_val(void) {
    return 1337;
}

int check_eq(int x, int y) {
    return x == y;
}

void correct() {
    puts("Correct!");
    puts("Here is your flag: grey{i_am_a_reverse_engineer!}");
}

void wrong() {
    puts("Wrong. Try again!");
}

int main(void) {
    int a, b;
    a = get_inp();
    b = get_val();
    if (check_eq(a, b)) {
        correct();
    } else {
        wrong();
    }
}

// int main(void) {
//     int var_28645749, var_33970782;
//     var_28645749 = sub_95735600();
//     var_33970782 = sub_73343031();
//     if (sub_29175793(var_28645749, var_33970782)) {
//         sub_84620595();
//     } else {
//         sub_82700889();
//     }
//     return 0;
// }
