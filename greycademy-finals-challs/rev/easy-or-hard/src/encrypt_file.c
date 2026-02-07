#include <unistd.h>
#include <time.h>
#include <chacha20_broken.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

int main(){
    char file_path[] = "./build/http_get_musl";
    int fd = open(file_path, O_RDONLY);
    if (fd == -1) {
        return 1;
    }
    size_t pl_len = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    char* buf = malloc(pl_len);
    read(fd, buf, pl_len);
    close(fd);
    char key[32] = {105, 177, 158, 89, 140, 47, 87, 132, 253, 10, 21, 142, 126, 155, 42, 80, 109, 98, 228, 20, 41, 188, 233, 236, 237, 104, 140, 149, 57, 152, 152, 152};
    char nonce[12] = {14, 27, 117, 98, 247, 51, 9, 28, 140, 72, 40, 84};
    struct chacha20_context ctx;
    chacha20_init_context(&ctx, key, nonce, 0);
    chacha20_xor(&ctx, buf, pl_len);
    printf("%zu\n", pl_len);
    printf("char buf [PL_LEN] = {");
    for(size_t i = 0; i < pl_len; i++) {
        printf("%u", (unsigned char)buf[i]);
        if(i != pl_len - 1) {
            printf(", ");
        }
    }
    printf("};\n");
    free(buf);
}
