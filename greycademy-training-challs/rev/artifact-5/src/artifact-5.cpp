// g++ -s -o artifact-5 artifact-5.cpp
#include <cstring>
#include <iostream>
#include <string>

unsigned int weights[] = { 2, 7, 6, 5, 4, 3, 2 };
char finals[] = "abcdefghizj";

int to_digit(char x) {
    if (x > '/' && x < ':') {
        return x - '0';
    }
    return -1;
}

int checksum(unsigned int value, char target) {
    unsigned int index = 10 - (((value * 4) % 44) / 4);
    return ((target | 0x20) == finals[index]);
}

int check(const char *inp) {
    if (strlen(inp) != 9 || (*inp | 0x20) != 't') {
        return 0;
    }
    unsigned int res = 0;
    unsigned int year = 0;
    for (int i = 0; i < 7; i++) {
        unsigned int cur = to_digit(*(inp + i + 1));
        if (cur == -1) {
            return 0;
        }
        res += cur * weights[i];
        if (i < 2) {
            year *= 10;
            year += cur;
        }
    }
    if (year > 26) {
        return 0;
    }
    return checksum(res + 4, *(inp + 8));
}

int main(void) {
    std::string input;
    std::cout << "Are you a valid member?" << std::endl;
    std::cout << "Enter serial number: ";
    std::cin >> input;
    const char *inp = input.c_str();
    if (check(inp)) {
        std::cout << "Welcome back!" << std::endl;
    } else {
        if ((*inp | 0x20) == 's') {
            std::cout << "[Unc detected]" << std::endl;
        }
        std::cout << "Impostor alert!!!" << std::endl;
    }
    return 0;
}
