#define SIG_READ(name) int name(int fd, void *buffer, size_t size)

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

SIG_READ(dome_read) {
    return read(fd, buffer, size);
}

int dome_printf(const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    int ret = vprintf(format, ap);
    va_end(ap);
    return ret;
}

fn_read request_read() {
    return dome_read;
}

fn_printf request_printf() {
    return dome_printf;
}

#endif
