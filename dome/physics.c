#include <stddef.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "syscalldef.h"

extern int main(int argc, char **argv);

void block_syscalls() {
    // Appears to be useless (even fail!), but somewhere I read it was required
    //SYSCALL(1, __NR_prctl, 0);
    long int res = SYSCALL(prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (res == -1)
        SYSCALL(exit, -2);

#define JUMP_EQ(K, Y, N) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, K, Y, N)
#define SEC_FIELD(field) (offsetof(struct seccomp_data, field))
    struct sock_filter filter[] = {
		/* [0] Load architecture from 'seccomp_data' buffer into accumulator */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SEC_FIELD(arch)),
		/* [1] Jump next instruction if architecture is X86_64 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        /* [2] Kill process */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        /* [3] Load syscall nr into accumulator */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SEC_FIELD(nr)),
        /* Jump 1 if syscall is exit */
        JUMP_EQ(__NR_exit, 1, 0),
        /* Jump 1 if syscall is NOT brk */
        JUMP_EQ(__NR_brk, 0, 1),
        /* Return cases */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (2/*EACCESS*/ & SECCOMP_RET_DATA)),
    };
#undef JUMP_EQ
#undef SEC_FIELD

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(*filter)),
        .filter = filter,
    };

    res = SYSCALL(seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
    if (res != 0)
        SYSCALL(exit, -2);
}

int32_t atoi(const char *str) {
    int result = 0;
    char ch;
    while((ch = *str++) && '0' <= ch && ch <= '9') {
        result = result * 10 + ch - '0';
    }
    return result;
}

// Assumes dst can hold 11 bytes if necessary:
// base10 number of digits of 2^31 + possible sign
// returns number of chars written to dst
int itoa(char *dst, int32_t v) {
    int count = 0;
    {
        int v_copy = v;
        do {
            count++;
            v_copy /= 10;
        } while(v_copy);
    }
    int is_negative = v < 0;
    if (is_negative) {
        v = -v;
        *dst++ = '-';
    }

    for (int i = count-1; i >= 0; i--) {
        dst[i] = '0'+ (v % 10);
        v /= 10;
    }
    return count + is_negative;
}

void print_int(int32_t v) {
    char buf[12];
    int len = itoa(buf, v);
    buf[len] = '\n';
    SYSCALL(write, 2, buf, len+1);
}

char chr_nibble(char v) {
    v &= 0x0f;
    if (v < 10)
        return '0'+v;
    else
        return 'a'+(v-10);
}

void print_hex64(u_int64_t v) {
    char digits[19] = "0x";
    for(int i = 0; i < 16; i++) {
        int offset = (15-i)*4;
        digits[i+2] = chr_nibble((v & (0x0fL<<offset)) >> (offset));
    }
    digits[sizeof(digits)-1] = '\n';
    SYSCALL(write, 2, digits, sizeof(digits));
}

void print_limit(int resource) {
    struct rlimit limit;
    SYSCALL(prlimit64, 0, resource, NULL, &limit);
    print_int(limit.rlim_cur);
}

int _enforce_physics_(int argc, char **argv) {
#ifdef STOP_AT_START // In case we don't follow the ptrace route
    int pid = SYSCALL(getpid);
    if (pid < 0)
        SYSCALL(exit, -4); // -4 = -CHILD_ERR_GET_PID
    SYSCALL(kill, pid, SIGSTOP);
#endif

    print_limit(RLIMIT_CPU);
    print_limit(RLIMIT_AS);
    print_limit(RLIMIT_DATA);
    print_limit(RLIMIT_STACK);

    int shm_id = atoi(argv[1]);
    print_int(shm_id);
    long _ground = SYSCALL(shmat, shm_id, NULL, 0);
    print_hex64(_ground);
    if (_ground == -1) {
        SYSCALL(exit, -5);
    }

    int *ground = (int *)_ground;
    print_int(ground[0]);
    print_int(ground[1]);
    print_int(ground[2]);

    block_syscalls();
    print_limit(RLIMIT_STACK); // should fail to get limit and print anything
    return main(argc, argv);
}
