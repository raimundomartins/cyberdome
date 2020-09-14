#include <stddef.h>

typedef int (*fn_read)(int fd, void *buffer, size_t size);
typedef int (*fn_printf)(const char *format, ...);

#ifdef __cplusplus
extern "C" {
#endif
    fn_read request_read();
    fn_printf request_printf();
#ifdef __cplusplus
}
#endif
