#define SIG_READ(name) int name(int fd, void *buffer, size_t size)

// -- BEGIN EXPORT H --

//| BEGIN SH: grep '^\s*typedef.*size_t;'
#include <stddef.h>
//| END SH


//BEGIN SH: sed -e "s/^\([^/]\)/extern \1/" -e 's|^\s*//||'
//#ifdef __cplusplus
//extern "C" {
//#endif

//#ifdef DOME_CAN_READ
typedef SIG_READ((*fn_read));
fn_read request_read();
//#endif

//#ifdef DOME_CAN_PRINT
typedef int (*fn_printf)(const char *format, ...);
fn_printf request_printf();
//#endif

//#ifdef __cplusplus
//}
//#endif
//END SH

// -- END EXPORT H --

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
