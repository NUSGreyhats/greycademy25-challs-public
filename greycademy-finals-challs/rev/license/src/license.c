#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define LICENSE_LENGTH 14
#pragma optimize("", off)

int stage1(char part[]) {
    // rot13
    for (int i = 0; i < 4; ++i) {
        part[i] = part[i] - 5;
    }
    return strcmp(part, "1142") == 0;
}

// use UNSIGNED char & BITWISE or for rotate!
// `static` places `expect` array in .rodata section
int stage2(unsigned char part[]) {  
    // rol 5  
    static const unsigned char expect[4] = {0x66, 0x86, 0x06, 0x06};
    for (int i = 0; i < 4; ++i) {
        part[i] = part[i] << 5 | part[i] >> (8 - 5);
        if (part[i] != expect[i]) {
            return 0;
        }
    }
    return 1;
}

int stage3(char part[]) {
    // xor 0x55
    for (int i = 0; i < 4; ++i) {
        part[i] = part[i] ^ 0x55;
    }
    return strcmp(part, "mbmc") == 0;
}

int validate_license(char license[]) {
    char a[5], b[5], c[5];

    int n = 0;
    if (sscanf(license, "%4[0-9]-%4[0-9]-%4[0-9]%n", a, b, c, &n) != 3) {
        return 0;
    }
    return stage1(a) && stage2(b) && stage3(c);
}

int main() {
    // 6697-3400-8786
    char input[25];
    printf("Enter License: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;

    if (strlen(input) == LICENSE_LENGTH && validate_license(input)) {
        printf("Congrats! The flag is grey{%s}\n", input);
    } else {
        printf("Wrong!\n");
    }
}
