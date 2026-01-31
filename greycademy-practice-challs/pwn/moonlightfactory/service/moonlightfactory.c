// gcc moonlightfactory.c -o moonlightfactory
#include <stdio.h>
#include <string.h>

void ignore_me() {
	setbuf(stdin, 0);
	setbuf(stdout, 0);
}

int main() {
	ignore_me();
    char printf_buffer[32];
    char overflow_buffer[8];
    
    printf("Enter your printf payload > ");
    fgets(printf_buffer, 31, stdin);
    printf(printf_buffer);
    printf("Enter your buffer overflow payload > ");
    gets(overflow_buffer);
    
    return 0;
}
