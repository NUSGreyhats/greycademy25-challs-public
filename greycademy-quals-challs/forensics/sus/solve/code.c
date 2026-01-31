// crackme.c
// Build: gcc -O2 -s crackme.c -o crackme
// Run:   ./crackme

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

static const uint8_t kXorKey = 0x5A;

static const uint8_t enc_a[] = {
  // First half (XORed with 0x5A)
  0x3d, 0x28, 0x3f, 0x23, 0x21, 0x28, 0x3f, 0x2c, 0x05, 0x3b, 0x34, 0x3e, 0x05, 0x3c, 0x35, 0x28, 0x3f, 0x34, 0x29, 0x05
};
static const uint8_t enc_b[] = {
  // Second half (XORed with 0x5A)
    0x3d, 0x35, 0x05, 0x32, 0x3b, 0x34, 0x3e, 0x05, 0x33, 0x34, 0x05, 0x32, 0x3b, 0x34, 0x3e, 0x7b, 0x66, 0x69, 0x27
};

static void decode_flag(char* flag_buf, size_t out_sz) {
    for (int i = 0; i < out_sz; i++) {
        if (i < sizeof(enc_a)) {
            flag_buf[i] = kXorKey ^ enc_a[i];
        } else {
            flag_buf[i] = kXorKey ^ enc_b[i - sizeof(enc_a)];
        }
    }
}

int main(void) {
  char input[256];

  puts("=== crackme ===");
  fputs("Enter flag: ", stdout);
  fflush(stdout);

  if (!fgets(input, sizeof(input), stdin)) {
    puts("Input error.");
    return 1;
  }

  const size_t flag_len = sizeof(enc_a) + sizeof(enc_b);
  char *flag = (char *)malloc(flag_len + 1);
  if (!flag) {
    puts("Memory error.");
    return 1;
  }

  decode_flag(flag, flag_len);
  int ok = strncmp(input, flag, flag_len);

  if (ok == 0) {
    puts("Correct!");
    return 0;
  } else {
    puts("Nope.");
    return 1;
  }
}
