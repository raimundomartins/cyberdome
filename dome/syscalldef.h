#include <sys/syscall.h>

/* Linux uses a negative return value to indicate syscall errors,
   unlike most Unices, which use the condition codes' carry flag.
   Since version 2.1 the return value of a system call might be
   negative even if the call succeeded.         E.g., the `lseek' system call
   might return a large offset.         Therefore we must not anymore test
   for < 0, but test for a real error by making sure the value in %eax
   is a real error number.  Linus said he will make sure the no syscall
   returns a value in -1 .. -4095 as a valid result so we can savely
   test with -4095.  */

/* The Linux/x86-64 kernel expects the system call parameters in
   registers according to the following table:
    syscall number       rax
    arg 1                rdi
    arg 2                rsi
    arg 3                rdx
    arg 4                r10
    arg 5                r8
    arg 6                r9
    The Linux kernel uses and destroys internally these registers:
    return address from syscall     rcx
    eflags from syscall             r11
    Normal function call, including calls to the system call stub
    functions in the libc, get the first six parameters passed in
    registers and the seventh parameter and later on the stack.  The
    register use is as follows:
     system call number   in the DO_CALL macro
     arg 1                rdi
     arg 2                rsi
     arg 3                rdx
     arg 4                rcx
     arg 5                r8
     arg 6                r9
    We have to take care that the stack is aligned to 16 bytes.  When
    called the stack is not aligned since the return address has just
    been pushed.
    Syscalls of more than 6 arguments are not supported.  */

#define SET_REG(reg, name, arg) register __typeof__((arg)-(arg)) name asm (reg) = (__typeof__((arg)-(arg)))(arg)
#define SET_REG0()
#define SET_REG1(arg1)                               SET_REG("rdi", _a1, arg1); SET_REG0()
#define SET_REG2(arg1, arg2)                         SET_REG("rsi", _a2, arg2); SET_REG1(arg1)
#define SET_REG3(arg1, arg2, arg3)                   SET_REG("rdx", _a3, arg3); SET_REG2(arg1, arg2)
#define SET_REG4(arg1, arg2, arg3, arg4)             SET_REG("r10", _a4, arg4); SET_REG3(arg1, arg2, arg3)
#define SET_REG5(arg1, arg2, arg3, arg4, arg5)       SET_REG("r8",  _a5, arg5); SET_REG4(arg1, arg2, arg3, arg4)
#define SET_REG6(arg1, arg2, arg3, arg4, arg5, arg6) SET_REG("r9",  _a6, arg6); SET_REG5(arg1, arg2, arg3, arg4, arg5)
#define USE_REG(var) "r" (var)
#define USE_REG0
#define USE_REG1 USE_REG0, USE_REG(_a1)
#define USE_REG2 USE_REG1, USE_REG(_a2)
#define USE_REG3 USE_REG2, USE_REG(_a3)
#define USE_REG4 USE_REG3, USE_REG(_a4)
#define USE_REG5 USE_REG4, USE_REG(_a5)
#define USE_REG6 USE_REG5, USE_REG(_a6)

#define SYSCALL(num_params, sys_num, ...) ({ \
    unsigned long int resultvar; \
    SET_REG##num_params(__VA_ARGS__); \
    asm volatile ( \
        "syscall\n\t" \
        : "=a" (resultvar) \
        : "0" (sys_num) USE_REG##num_params \
        : "memory", "cc", "r11", "cx"); \
    (long int) resultvar; \
})

#define ERRNO_SYSCALL(num_params, sys_num, ...) ({ \
    long resultvar = SYSCALL(num_params, sys_num, __VA_ARGS__); \
	if (resultvar > -4096) { \
        errno = -resultvar; \
        resultvar = -1; \
    } \
    resultvar; \
})

