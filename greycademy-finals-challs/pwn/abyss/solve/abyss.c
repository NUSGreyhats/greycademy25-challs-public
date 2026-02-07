// gcc ./abyss.c -no-pie -o ./abyss
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
    printf("You find light at the end of the tunnel!\n");
    system("/bin/sh");
}

struct Data {
    char buf[40];
    int cur_idx;
};

int main() {
    setup();
    struct Data data;
    data.cur_idx = 0;
    char nxt;
    for (int i = 0; i < 0x40; i++) {
        printf("Scream into the abyss: ");
        scanf("%c", &nxt);
        getchar();
        data.buf[data.cur_idx++] = nxt;
    }
    return 0;
}