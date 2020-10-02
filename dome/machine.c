#include <stddef.h>
#include "syscalldef.h"
//#include <unistd.h>

#if 0
size_t read(int fd, void *buf, size_t count) {
    return SYSCALL(3, __NR_read, fd, buf, count);
}

size_t write(int fd, const void *buf, size_t count) {
    return SYSCALL(3, __NR_write, fd, buf, count);
}
#endif

static char *itoa(unsigned long num, char *dest) {
    int digits = 1;
    while(num / digits)
        digits *= 10;
    for(digits /= 10; digits; digits /= 10) {
        *dest++ = ((num/digits)%10) + '0';
    }
    return dest;
}

int main2(int argc, char **argv) {
    char buf[40];
    const char *intro = "Addr = 0x";
    int i = 0;
    for (; intro[i]; intro++)
        buf[i] = intro[i];
    char *bufend = itoa(argc, buf+i);
    *bufend++ = '\n';
    *bufend = '\0';
    return buf[0];//write(1, buf, bufend - buf);
}
