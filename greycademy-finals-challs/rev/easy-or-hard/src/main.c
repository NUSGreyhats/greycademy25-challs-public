#define _GNU_SOURCE         /* See feature_test_macros(7) */

#include <stdio.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <time.h>
#include <chacha20_broken.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#define PL_LEN 0
char buf[PL_LEN] = {};

bool debuggerIsAttached()
{
    char buf[4096];

    const int status_fd = open("/proc/self/status", O_RDONLY);
    if (status_fd == -1)
        return false;

    const ssize_t num_read = read(status_fd, buf, sizeof(buf) - 1);
    close(status_fd);

    if (num_read <= 0)
        return false;

    buf[num_read] = '\0';
    char tracerPidString[] = "rPid:";
    char* tracer_pid_ptr = strstr(buf, tracerPidString);
    if (!tracer_pid_ptr)
        return false;

    for (const char* characterPtr = tracer_pid_ptr + sizeof(tracerPidString) - 1; characterPtr <= buf + num_read; ++characterPtr)
    {
        if (isspace(*characterPtr))
            continue;
        else
            return isdigit(*characterPtr) != 0 && *characterPtr != '0';
    }

    return false;
}

int main(){
    struct timespec ts;
    unsigned theTick = 0U;
    clock_gettime( CLOCK_REALTIME, &ts );
    theTick  = ts.tv_nsec / 10000;

    if(debuggerIsAttached()){
        return 1;
    }

    char key[32] = {105, 177, 158, 89, 140, 47, 87, 132, 253, 10, 21, 142, 126, 155, 42, 80, 109, 98, 228, 20, 41, 188, 233, 236, 237, 104, 140, 149, 57, 152, 152, 152};
    char nonce[12] = {14, 27, 117, 98, 247, 51, 9, 28, 140, 72, 40, 84};
    struct chacha20_context ctx;
    chacha20_init_context(&ctx, key, nonce, 0);
    chacha20_xor(&ctx, buf, PL_LEN);

    int fd = memfd_create("easy_or_hard", MFD_CLOEXEC);
    write(fd, buf, PL_LEN);

    clock_gettime( CLOCK_REALTIME, &ts );
    theTick = (ts.tv_nsec / 10000) - theTick;
    if(theTick > 1000){
        return 1;
    }
    puts("Outputting the flag...");
    fexecve(fd, NULL, NULL);
}