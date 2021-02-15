#define SIG_READ(name) ssize_t name(void *buffer, size_t size)

//| BEGIN SH: grep '^\s*typedef.*size_t;'
#include <stddef.h>
//| END SH

typedef SIG_READ((*fn_read));
extern fn_read request_read(); // EXPORT IF DOME_CAN_READ

typedef int (*fn_printf)(const char *format, ...);
extern fn_printf request_printf(); // EXPORT

#ifndef HEADER_ONLY

#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include "syscalldef.h"

SIG_READ(dome_read) {
    return SYSCALL(3, __NR_read, 0, buf, count);
}

#if 0
int dome_printf(const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    int ret = vprintf(format, ap);
    va_end(ap);
    return ret;
}
#endif

fn_read request_read() {
    return dome_read;
}

#if 0
fn_printf request_printf() {
    return dome_printf;
}
#endif

size_t write(const void *buf, size_t count) {
    return SYSCALL(3, __NR_write, 1, buf, count);
}

#if 0
char *itoa(unsigned long num, char *dest) {
    int digits = 1;
    while(num / digits)
        digits *= 10;
    for(digits /= 10; digits; digits /= 10) {
        *dest++ = ((num/digits)%10) + '0';
    }
    return dest;
}
#endif

#endif
