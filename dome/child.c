#include <stddef.h>
#include <sys/auxv.h>
#include "syscalldef.h"
#include <unistd.h>

//size_t read(int fd, void *buf, size_t count) {
//    return SYSCALL(3, __NR_read, fd, buf, count);
//}

//size_t write(int fd, const void *buf, size_t count) {
//    return SYSCALL(3, __NR_write, fd, buf, count);
//}

char *itoa(unsigned long num, char *dest) {
    int digits = 1;
    while(num / digits)
        digits *= 10;
    for(digits /= 10; digits; digits /= 10) {
        *dest++ = ((num/digits)%10) + '0';
    }
    return dest;
}

int main(int argc, char **argv) {
    char buf[40];
    const char *intro = "Addr = 0x";
    int i = 0;
    for (; intro[i]; intro++)
        buf[i] = intro[i];
    char *bufend = itoa(getauxval(AT_EUID), buf+i);
    *bufend++ = '\n';
    *bufend = '\0';
    return write(1, buf, bufend - buf);
}
