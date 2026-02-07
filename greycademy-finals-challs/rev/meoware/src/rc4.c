
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define N 256   // 2^8

__attribute__((always_inline))
void swap(unsigned char *a, unsigned char *b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

__attribute__((always_inline))
int KSA(char *key, size_t key_len, unsigned char *S) {

    int j = 0;

    for(int i = 0; i < N; i++)
        S[i] = i;

    for(int i = 0; i < N; i++) {
        j = (j + S[i] + key[i % key_len]) % N;

        swap(&S[i], &S[j]);
    }

    return 0;
}

__attribute__((always_inline))
int PRGA(unsigned char *S, char *plaintext, unsigned char *ciphertext, size_t length) {

    int i = 0;
    int j = 0;

    for(size_t n = 0; n < length; n++) {
        i = (i + 1) % N;
        j = (j + S[i]) % N;

        swap(&S[i], &S[j]);
        int rnd = S[(S[i] + S[j]) % N];

        ciphertext[n] = rnd ^ plaintext[n];

    }

    return 0;
}

int rc4_crypt(char *key, size_t keylen, char *plaintext, unsigned char *ciphertext, size_t length) {
    unsigned char S[N];
    KSA(key, keylen, S);
    PRGA(S, plaintext, ciphertext, length);
    return 0;
}