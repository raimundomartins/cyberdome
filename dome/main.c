#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define GO_FORK

#define PRINTERRNO(callname) do { \
    int err = errno; \
    fprintf(stderr, __FILE__":%d: " #callname " failed with error %d: '%s'\n", \
            __LINE__, err, strerror(err)); \
} while(0)

unsigned print_syscall(FILE *fp, long nr) {
#define SYSCALL_MAP(call) [__NR_##call] = #call
    static const char *syscalls[] = {
        SYSCALL_MAP(execve),
        SYSCALL_MAP(brk),
        SYSCALL_MAP(open),
        SYSCALL_MAP(openat),
        SYSCALL_MAP(write),
        SYSCALL_MAP(read),
        SYSCALL_MAP(close),
        SYSCALL_MAP(fstat),
        SYSCALL_MAP(access),
        SYSCALL_MAP(mmap),
        SYSCALL_MAP(munmap),
        SYSCALL_MAP(mprotect),
        SYSCALL_MAP(arch_prctl),
        SYSCALL_MAP(exit_group),
    };
#undef SYSCALL_MAP
    if (nr < sizeof(syscalls)/sizeof(*syscalls) && syscalls[nr] != NULL) {
        size_t len = strlen(syscalls[nr]);
        fprintf(fp, "%s", syscalls[nr]);
        return len;
    }
    else {
        fprintf(fp, "%5lld", nr);
        return 5;
    }
}

int child(void *arg) {
#ifdef GO_FORK
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        PRINTERRNO(ptrace);
        return -3;
    }
#endif

    if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        PRINTERRNO(prctl);
    }

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
/*        SKIP_IF_SYSCALL(uname, 10),
        SKIP_IF_SYSCALL(arch_prctl, 9),
        SKIP_IF_SYSCALL(open, 7),
        SKIP_IF_SYSCALL(read, 6),*/
/*        JUMP_EQ(__NR_openat, 8, 0),
        JUMP_EQ(__NR_write, 7, 0),
        JUMP_EQ(__NR_sync, 6, 0),*/
        JUMP_EQ(__NR_exit, 9, 0),
        JUMP_EQ(__NR_execve, 8, 0),
        JUMP_EQ(__NR_brk, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SEC_FIELD(args[0])),
        JUMP_EQ(0, 1, 1),
        /* Return cases */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EACCES & SECCOMP_RET_DATA)),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SEC_FIELD(args[0])),
        BPF_STMT(BPF_ALU | BPF_K | BPF_AND, SECCOMP_RET_DATA),
        BPF_STMT(BPF_ALU | BPF_K | BPF_OR, SECCOMP_RET_TRACE),
        BPF_STMT(BPF_RET | BPF_A, 0),
//        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | (10 & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(*filter)),
        .filter = filter,
    };

    long seccomp_res = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog); 
    switch(seccomp_res) {
    case -1: 
        PRINTERRNO(syscall);
        return -2;
    case 0: break;
    default:
        fprintf(stderr, "seccomp failed to synchronize with thread id %ld\n",
                seccomp_res);
    }
#if 1
    execl("child", "child", (char *)NULL);
#else
    int exe = syscall(__NR_execveat, exefd, "",
                       (char *const []){ "/usr/bin/id", "argh", NULL },
                       (char *const []){ NULL },
                       AT_EMPTY_PATH);
#endif
    PRINTERRNO(execl);
    return -1;
}

int main(int argc, char **argv) {
    printf("Pid: %ld\n", getpid());
    char stack[2048];
    for (int i = 0; i < sizeof(stack); i++) {
        stack[i] = 'a'+i%(1+'z'-'a');
    }
    stack[sizeof(stack)-1] = '\0';
    printf("\tstack\t%p\n", stack);
    //for (int i = 0; i < sizeof(stack); i++) { putchar(stack[i]); }
    printf("\tstack e\t%p\t", stack+sizeof(stack));
    printf("\n");
#ifndef GO_FORK
    child(NULL);
#else
    int pid = clone(child, stack+sizeof(stack), CLONE_VM|SIGCHLD, stack);
    if (pid == -1) {
        fprintf(stderr, "No clone: %s\n", strerror(errno));
        exit(1);
    }
    printf("Child pid: %d\n", pid);

    // Actually we should wait for child signal that it setup ptrace and
    // signal it back after we are done setting up, but hey.. this is easier :D
    unsigned long ptrace_opts = PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL;
    while (ptrace(PTRACE_SETOPTIONS, pid, NULL, ptrace_opts) == -1) {
        if (errno != ESRCH) {
            PRINTERRNO(ptrace);
            return -1;
        }
    }

    printf("Message\t      %%rip      \tSyscall\t\
\t      Arg1      \t      Arg2      \t      Arg3      \
\t      Arg4      \t      Arg5      \t      Arg6      \n");
    int status;
    while(waitpid(pid, &status, 0)) {
        if (WIFEXITED(status)) {
            fprintf(stderr, "Tracee quit! Bye!\n");
            break;
        }
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            unsigned long msg;
            if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &msg) == -1) {
                PRINTERRNO(ptrace);
            }
            fprintf(stderr, "%6ld\t", msg & SECCOMP_RET_DATA);
            struct user_regs_struct regs;
            memset(&regs, 0, sizeof(regs));
            if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
                PRINTERRNO(ptrace);
                continue;
            }
            errno = 0;
            long instruction = ptrace(PTRACE_PEEKDATA, pid, regs.rip, NULL);
            if (instruction == -1 && errno != 0) {
                PRINTERRNO(ptrace);
            }
            fprintf(stderr, "0x%016llx\t", regs.rip);
            if (print_syscall(stderr, regs.orig_rax) < 8) {
                fprintf(stderr, "\t");
            }
            long args[6] = { regs.rdi, regs.rsi, regs.rdx,
                regs.r10, regs.r8, regs.r9 };
            struct {
                long v;
                int err;
            } vals[sizeof(args)/sizeof(*args)];
            for (int i = 0; i < sizeof(args)/sizeof(*args); i++) {
                fprintf(stderr, "\t0x%016llx", args[i]);
                errno = 0;
                vals[i].v = ptrace(PTRACE_PEEKDATA, pid, args[i], NULL);
                vals[i].err = errno;
            }
            fprintf(stderr, "\n\t\t\t\t\t");
            for (int i = 0; i < sizeof(args)/sizeof(*args); i++) {
                if (vals[i].err)
                    fprintf(stderr, "\t       NULL      ");
                else
                    fprintf(stderr, "\t0x%016llx", vals[i].v);
            }
            fprintf(stderr, "\n\t\t\t\t\t");
            for (int i = 0; i < sizeof(args)/sizeof(*args); i++) {
                if (vals[i].err)
                    fprintf(stderr, "\t\"                \"");
                else {
                    char buf[18];
                    int bufi = 0;
                    for (int j = 0; j < 8; j++) {
                        char c = (vals[i].v>>(j<<3))&0xff;
                        if (c < 0) {
                            buf[bufi++] = '\\';
                            buf[bufi++] = '?';
                            continue;
                        }
                        switch (c) {
                        case 0: buf[bufi++] = '\\'; buf[bufi++] = '0'; break;
                        case '\n': buf[bufi++] = '\\'; buf[bufi++] = 'n'; break;
                        case '\t': buf[bufi++] = '\\'; buf[bufi++] = 't'; break;
                        default: buf[bufi++] = c; break;
                        }
                    }
                    buf[bufi++] = '"';
                    while (bufi < 17) buf[bufi++] = ' ';
                    buf[17] = '\0';
                    fprintf(stderr, "\t\"%s", buf);
                }
            }
            fprintf(stderr, "\n");
            if (regs.orig_rax == __NR_execve) {
                struct rlimit old;
                memset(&old, 0, sizeof(old));
                const struct rlimit data = { 4096*13, 4096*13 };
                prlimit(pid, RLIMIT_DATA, &data, &old);
                fprintf(stderr, "OLD DATA SPACE: %ld; %ld\n", old.rlim_cur, old.rlim_max);
                memset(&old, 0, sizeof(old));
                const struct rlimit stack = { 4096*5, 4096*5 };
                prlimit(pid, RLIMIT_STACK, &stack, &old);
                fprintf(stderr, "OLD STACK SPACE: %ld; %ld\n", old.rlim_cur, old.rlim_max);
            }
        }
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
            PRINTERRNO(ptrace);
        }
    }
#endif
    return 0;
}
