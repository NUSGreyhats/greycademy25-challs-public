// gcc -o artifact-14 artifact-14.c
// gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0

#include <stdio.h>
#include <string.h>

#define SIZE 29
char dst[] = "abcdefghijklmnopqrstuvwxyz_{}";
char *inter[SIZE];
char **src[SIZE];

void setup(void) {
    for (int i = 0; i < SIZE; i++) {
        inter[i] = &dst[i];
    }
    for (int i = 0; i < SIZE; i++) {
        src[i] = &inter[i];
    }
}
int check(char *inp, char ***ptr);

int main(void) {
    setup();
    /*
     Welcome!
     Pointers are conceptually just indices of some big array (the memory).
     But it does have some (potentially unintuitive) quirks, especially around pointer arithmetic.
     Suggested resources:
      -  https://www.youtube.com/watch?v=9B1zGvz-leI (UNTIL 5:50)
      -  https://www.youtube.com/watch?v=2ybLD6_2gKM
      -  https://www.youtube.com/watch?v=ZNjg_7nxsz4 (nice visualization, but may contain
                                                      some advanced (out-of-scope) content)
     */
    char ***ptr = src;
    char inp[32];
    printf("Enter flag: >>> ");
    fgets(inp, 31+1, stdin); // +1 for null byte
    if (check(inp, ptr)) {
        puts("Correct!");
    } else {
        puts("Wrong!");
    }
    return 0;
}

int check(char *inp, char ***ptr) {
    if (strlen(inp) != 31) return 0;
    // Looks scary? That's intentional!
    // !!! REFER TO THE BOTTOM OF THIS FILE FOR SOME HELP !!!
    //
    // Note you can probably refer to the IDA decompilation.
    // It is an "easier" version due to optimisations, but not by much.
    // Please only refer to it when you're really stuck. This is good practice :P
    if (inp[0] != *(*(char **)((double *)(*(long **)((long *)((unsigned char *)ptr+24)+11)-6)+5)-7)) return 0;
    if (inp[1] != *(*(char **)((char *)(*(unsigned short **)((int *)((unsigned long *)ptr+19)+18)-32)+8)-4)) return 0;
    if (inp[2] != *(*(char **)((unsigned char *)(*(unsigned long **)((char *)((short *)ptr+36)-32)+0)+128)-17)) return 0;
    if (inp[3] != *(*(char **)((double *)(*(long **)((int *)((unsigned char *)ptr+120)-16)+16)-23)+24)) return 0;
    if (inp[4] != *(*(char **)((unsigned int *)(*(short **)((float *)((long *)ptr+20)+16)-96)+24)+11)) return 0;
    if (inp[5] != *(*(char **)((void **)(*(unsigned short **)((unsigned long *)((char *)ptr+176)+2)-16)+1)-6)) return 0;
    if (inp[6] != *(*(char **)((long *)(*(unsigned int **)((char *)((long *)ptr+26)+16)-46)+12)+3)) return 0;
    if (inp[7] != *(*(char **)((short *)(*(unsigned short **)((unsigned long *)((char *)ptr+152)-8)-44)+76)+6)) return 0;
    if (inp[8] != *(*(char **)((void **)(*(unsigned short **)((short *)((char *)ptr+216)-32)+16)-9)+11)) return 0;
    if (inp[9] != *(*(char **)((short *)(*(double **)((char *)((unsigned char *)ptr+96)-32)+7)+32)-12)) return 0;
    if (inp[10] != *(*(char **)((long *)(*(void ***)((float *)((unsigned short *)ptr+64)-32)+20)-11)-5)) return 0;
    if (inp[11] != *(*(char **)((long *)(*(int **)((long *)((float *)ptr+6)-1)+24)+10)+2)) return 0;
    if (inp[12] != *(*(char **)((unsigned long *)(*(short **)((char *)((unsigned short *)ptr+112)-16)-40)+11)-27)) return 0;
    if (inp[13] != *(*(char **)((int *)(*(unsigned long **)((unsigned int *)((unsigned long *)ptr+7)-8)+22)-32)+4)) return 0;
    if (inp[14] != *(*(char **)((unsigned int *)(*(float **)((long *)((double *)ptr+16)+5)+8)-48)+2)) return 0;
    if (inp[15] != *(*(char **)((unsigned short *)(*(float **)((int *)((void **)ptr+3)-2)+38)-28)+12)) return 0;
    if (inp[16] != *(*(char **)((unsigned short *)(*(int **)((double *)((unsigned char *)ptr+32)+5)+24)-16)-2)) return 0;
    if (inp[17] != *(*(char **)((void **)(*(float **)((unsigned long *)((char *)ptr+224)-9)-38)+8)+6)) return 0;
    if (inp[18] != *(*(char **)((unsigned short *)(*(int **)((double *)((float *)ptr+50)-1)-46)+16)+3)) return 0;
    if (inp[19] != *(*(char **)((unsigned int *)(*(unsigned long **)((char *)((short *)ptr+56)+96)-10)-24)+9)) return 0;
    if (inp[20] != *(*(char **)((void **)(*(double **)((unsigned int *)((unsigned char *)ptr+168)+0)+5)-24)+17)) return 0;
    if (inp[21] != *(*(char **)((unsigned int *)(*(void ***)((double *)((double *)ptr+11)+10)-20)+36)-15)) return 0;
    if (inp[22] != *(*(char **)((unsigned char *)(*(unsigned long **)((unsigned char *)((unsigned short *)ptr+108)-168)-3)+200)-11)) return 0;
    if (inp[23] != *(*(char **)((double *)(*(unsigned int **)((unsigned long *)((float *)ptr+2)+8)+28)-14)+17)) return 0;
    if (inp[24] != *(*(char **)((void **)(*(unsigned long **)((unsigned char *)((char *)ptr+152)-40)+8)+4)-22)) return 0;
    if (inp[25] != *(*(char **)((double *)(*(int **)((int *)((unsigned int *)ptr+42)-12)+4)+2)+4)) return 0;
    if (inp[26] != *(*(char **)((char *)(*(unsigned int **)((char *)((unsigned short *)ptr+48)-56)+36)-184)+15)) return 0;
    if (inp[27] != *(*(char **)((float *)(*(unsigned int **)((float *)((float *)ptr+10)-6)+16)+36)-24)) return 0;
    if (inp[28] != *(*(char **)((char *)(*(float **)((unsigned long *)((unsigned char *)ptr+144)-16)+10)+40)+5)) return 0;
    if (inp[29] != *(*(char **)((void **)(*(unsigned char **)((char *)((void **)ptr+21)-64)+8)-4)+9)) return 0;
    if (inp[30] != *(*(char **)((unsigned int *)(*(unsigned int **)((unsigned short *)((long *)ptr+15)+8)-12)-10)+22)) return 0;
    // Once you've found the overarching pattern, you might want to make it less tedious by writing a script?
    // (completely optional!!)
    return 1;
}

/*

(Hopefully) helpful tips to get you started!

===================================================================================
WHAT IS PTR, SRC, INTER, DST?
Hopefully you realise that each check eventually resolves to some character in dst.
This is done via pointer dereferencing.
Right now, it looks something like this:

   char dst[]   [0] [1] [2] [3] [4] ...
               ┬───┬───┬───┬───┬───┬───┬
         ADDR  │100│101│102│103│104│...│
               ╔═══╗───┼───┼───┼───┼───┼
        VALUE  ║'a'║'b'│'c'│'d'│'e'│...│
               ╚═╤═╝───┴───┴───┴───┴───┴
                 └───┐
                     │
char *inter[]   [0]  │                          [1]                             [2]     ...
               ┬───┬─│─┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬
         ADDR  │200│201│202│203│204│205│206│207│208│209│210│211│212│213│214│215│216│217│...│
               ╔═══╧═│═╧═══╧═══╧═══╧═══╧═══╧═══╗───┴───┴───┴───┴───┴───┴───┴───┼───┴───┴───┼
        VALUE  ║     └─── (char *)100          ║          (char *)101          │  102   ...│ each element holds the
               ╚═╤═════════════════════════════╝───────────────────────────────┴───────────┴ address of some char
                 └───┐
                     │
 char **src[]   [0]  │                          [1]                             [2]     ...
               ┬───┬─│─┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬
         ADDR  │300│301│302│303│304│305│306│307│308│309│310│311│312│313│314│315│316│317│...│
               ╔═══╧═│═╧═══╧═══╧═══╧═══╧═══╧═══╗───╔═══╗───┴───┴───┴───╔═══╧═══╪═══╧═══╗───┼
        VALUE  ║     └── (char **) 200         ║   ║   ║ (char **) 208 ║       │  216  ║...│ each element holds the
               ╚═╤═════════════════════════════╝───╚═╤═╝───────────────╚═╤═════╧═══════╝───┴ address of some (char *)
                 │                                   │                   │
                 │                                   │                   │
  char ***ptr    │                                   │                   │
               ┬─│─┬───┬───┬───┬───┬───┬───┬───┬     │                   │
         addr  │ │      (not important)        │     │                   │
               ┼─│─┴───┴───┴───┴───┴───┴───┴───┼     │                   │
        value  │ └─────────── 300              │ holds the address of some (char **)
               └───────────────────────────────┘     │                   │
                                                     │                   │
                                                     │                   │
        (char *)ptr+9   ─────────────────────────────┘                   │
                        (char *) takes precedence over +                 │
(int *)((short *)ptr+7) ─────────────────────────────────────────────────┘
                        why +7 instead of +14? because ptr thinks it is overlooking an array of shorts (2 bytes each).
                        (before it gets casted to (int *))
                        that is, if we casted to (int *)ptr first, we would write +3.5 (though that is not possible).

                        (It might help to know that arr[x] is just another way to write *(arr+x) .)

To "select" a value (dereference) after shifting the pointer,
we simply prefix the expression with a *

So *(int *)((short *)ptr+7) will give us some garbage value (invalid pointer),
because the elements need to be 8 byte-aligned.

Whereas *(long *)((short *)ptr+8) will, effectively, give us the value 202.
Now the value is "valid", but the type is not a pointer (just a long).
Only pointers can be dereferenced, so be sure to add a cast before dereferencing.
===================================================================================

TYPES USED:           EACH +1 INCREMENTS BY:
(unsigned) char *     1 byte
(unsigned) short *    2 bytes
(unsigned) int *      4 bytes
(unsigned) long *     8 bytes
           float *    4 bytes
           double *   8 bytes
           void **    8 bytes <-- this points to another pointer (address value).

*/
