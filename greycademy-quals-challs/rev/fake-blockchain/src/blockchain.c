#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

// FLAG grey{struct5_4re_ug1y}
int EXPECTED[] = {
    0x18EF, 0xA5E, 0x17F1, 0x594, 0x1739, 0x498, 0x164D, 0x414, 0x15AE,
    0x766, 0x14F3, 0x692, 0x1432, 0x5A3, 0x1722, 0x4A4, 0x161C, 0x3B5,
    0x1106, 0x2B9, 0x1028, 0x1AA
};

typedef struct Block {
    char data;
    unsigned int hash;
    struct Block* prev;
} Block;

Block* ll = NULL;

unsigned int calculate_hash(char c, unsigned int prev_hash) {
    return (prev_hash + c) ^ 0x1234;
}

bool validate() {
    Block* current = ll;
    int index = 0;
    int expected_count = sizeof(EXPECTED) / sizeof(EXPECTED[0]);
    if (current == NULL) return false;
    while (current != NULL) {
        if (index >= expected_count) {
            return false;
        }
        unsigned int expected_hash = EXPECTED[index];
        if (current->hash != expected_hash) {
            return false;
        }
        current = current->prev;
        index++;
    }
    return true;
}

void view() {
    Block* current = ll;
    int index = 0;
    printf("=== Blocks [%s] ===\n", validate() ? "VALID" : "INVALID");
    while (current != NULL) {
        printf("ID-%d: Data='%c', Hash=0x%08X\n", index, current->data, current->hash);
        current = current->prev;
        index++;
    }
    printf("========================\n");
}


void add_data() {
    int length;
    printf("Length: ");
    if (scanf("%d", &length) != 1 || length <= 0) {
        printf("Invalid length\n");
        while (getchar() != '\n');
        return;
    }
    if (length > SIZE_MAX - 1) {
        printf("Length too large\n");
        return;
    }
    char* data = malloc(length + 1);
    if (!data) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    printf("Data: ");
    scanf("%*c");
    if (fgets(data, length + 1, stdin) == NULL) {
        free(data);
        return;
    }
    size_t actual_len = strlen(data);
    if (actual_len > 0 && data[actual_len - 1] == '\n') {
        data[actual_len - 1] = '\0';
        actual_len--;
    }

    for (size_t i = 0; i < actual_len; i++) {
        Block* new_block = malloc(sizeof(Block));
        if (!new_block) {
            fprintf(stderr, "Memory allocation failed\n");
            free(data);
            exit(1);
        }
        new_block->data = data[i];
        new_block->hash = calculate_hash(new_block->data, (ll == NULL) ? 0x1337 : ll->hash);
        new_block->prev = ll;
        ll = new_block;
    }
    free(data);
}

void banner() {
    printf("=== Greycademy Blockchain ===\n");
}
void menu() {
    printf("1. Add data\n");
    printf("2. View blocks\n");
    printf("3. Exit\n");
}

int main() {
    int choice;
    banner();
    do {
        menu();
        printf("> ");
        scanf("%d", &choice);
        if (choice == 1) {
            add_data();
        } else if (choice == 2) {
            view();
        } else if (choice == 3) {
            break;
        } else {
            printf("Invalid choice. Try again.\n");
        }
    } while (1);
    return 0;
}