#include "dome.h"
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>

int dome_read(int fd, void *buffer, size_t size) {
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
