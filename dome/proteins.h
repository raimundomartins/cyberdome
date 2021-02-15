typedef long int ptrdiff_t;
typedef long unsigned int size_t;
typedef int wchar_t;
typedef struct {
  long long __max_align_ll __attribute__((__aligned__(__alignof__(long long))));
  long double __max_align_ld __attribute__((__aligned__(__alignof__(long double))));
} max_align_t;
typedef ssize_t (*fn_read)(void *buffer, size_t size);
#ifdef __cplusplus
extern "C" {
#endif
#ifdef DOME_CAN_READ
extern fn_read request_read();
#endif
#ifdef __cplusplus
}
#endif
typedef int (*fn_printf)(const char *format, ...);
#ifdef __cplusplus
extern "C" {
#endif
extern fn_printf request_printf();
#ifdef __cplusplus
}
#endif
