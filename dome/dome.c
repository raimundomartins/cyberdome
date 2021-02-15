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

#define PRINTERRNO(callname) do { \
    int err = errno; \
    fprintf(stderr, __FILE__":%d: " #callname " failed with error %d: '%s'\n", \
            __LINE__, err, strerror(err)); \
} while(0)

enum child_err {
    CHILD_ERR_PTRACE = 1,
    CHILD_ERR_SECCOMP,
    CHILD_ERR_EXEC,
    CHILD_ERR_GET_PID,
};

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

struct exec_child_arg {
    const char *dna;
    int shmem_id;
};

enum child_err exec_child(void *arg) {
#define DOME_PTRACE
#ifdef DOME_PTRACE
    // We do not wait to PTRACE this child because on exec it triggers SIGCHLD
    // with code CLD_TRAPPED which we catch and handle
    fprintf(stderr, "Dome child setting up PTRACE\n");
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        PRINTERRNO(ptrace);
        return -CHILD_ERR_PTRACE;
    }
#endif

#ifdef DOME_SECCOMP
    fprintf(stderr, "Dome child setting up SECCOMP\n");
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
        return -CHILD_ERR_SECCOMP;
    case 0: break;
    default:
        fprintf(stderr, "seccomp failed to synchronize with thread id %ld\n",
                seccomp_res);
    }
#endif

    struct exec_child_arg *p = arg;
#if 1
    // Must send shmem_id and use shmat in the child. Maybe in a future version
    // we can make it through ptrace! (and seccomp as well!)
    fprintf(stderr, "Dome child going to exec '%s'\n", p->dna);
    execl(p->dna, "alpha", (char *)NULL);
#else
    int exe = syscall(__NR_execveat, exefd, "",
                       (char *const []){ "/usr/bin/id", "argh", NULL },
                       (char *const []){ NULL },
                       AT_EMPTY_PATH);
#endif
    PRINTERRNO(execl);
    exit(-CHILD_ERR_EXEC);
}

void set_limits(pid_t pid) {
#if 0
    char buf[12];
    SYSCALL(4, __NR_prlimit64, 0, resource, NULL, &limit);
    int len = itoa(buf, limit.rlim_max);
    buf[len] = '\n';
    SYSCALL(3, __NR_write, 1, buf, len);
#endif
    printf("Setting limits for %d\n", pid);
    int page_size = sysconf(_SC_PAGESIZE);
    struct rlimit limit;
    limit = (struct rlimit){ 2, 2 };
    prlimit(pid, RLIMIT_CPU, &limit, NULL);
    limit = (struct rlimit) { page_size, page_size };
    prlimit(pid, RLIMIT_AS, &limit, NULL);
    limit = (struct rlimit) { page_size, page_size };
    prlimit(pid, RLIMIT_DATA, &limit, NULL);
    limit = (struct rlimit) { 1, 1 };
    prlimit(pid, RLIMIT_STACK, &limit, NULL);
    printf("Done setting limits for %d\n", pid);
}

void on_sigchld(int signal, siginfo_t *info, void *data) {
    //switch(signal) { case SIGCHLD:
    printf("Child %d triggered signal because of %d\n", info->si_pid, info->si_code);
    switch(info->si_code) {
    case CLD_KILLED:
    case CLD_DUMPED:
        break;
    case CLD_EXITED:
        //Exit code is in info->si_status
        break;
    case CLD_TRAPPED:
        printf("Child %d trapped\n", info->si_pid);
        set_limits(info->si_pid);
        ptrace(PTRACE_DETACH, info->si_pid, NULL, NULL);
        break;
    case CLD_CONTINUED:
        break;
    case CLD_STOPPED:
        printf("Child %d stopped by signal %d\n", info->si_pid, info->si_status);
        switch(info->si_status) {
        case SIGSTOP:
            set_limits(info->si_pid);
            kill(info->si_pid, SIGCONT);
            break;
        case SIGCONT:
            break;
        case SIGXCPU:
            break;
        case SIGSEGV:
            printf("Child segmentation fault\n");
        }
        break;
    }
}

pid_t create_child(const char *dna, int shmem_id) {
    pid_t child_pid = fork();
    switch(child_pid) {
    case -1: // Error
        fprintf(stderr, "No clone: %s\n", strerror(errno));
        break;
    case 0: { // Child
        char *dna_cp = strdup(dna);
        fprintf(stderr, "Child going to exec %s\n", dna_cp);
        exec_child(&(struct exec_child_arg){ dna_cp, shmem_id });
        //Does not return
    }
    default: // Parent
        printf("Child pid: %d\n", child_pid);
    }
    return child_pid;
}

int main(int argc, char **argv) {
    printf("Parent pid = %ld\n", getpid());

    {
        int page_size = sysconf(_SC_PAGESIZE);
        printf("Page size = %d\n", page_size);
    }

    // Setup SIGCHLD
    struct sigaction child_action;
    child_action.sa_sigaction = on_sigchld;
    sigemptyset(&child_action.sa_mask);
    child_action.sa_flags = SA_SIGINFO | SA_NOCLDWAIT;
    sigaction(SIGCHLD, &child_action, NULL);

    pid_t pid = create_child(argv[1], 1);
    sleep(1);
    while(1) {
        //printf("Sleeping");
        for(int i = 10; i > 0; i--) {
            //printf(" %d...", i);
            //fflush(stdout);
            sleep(1);
        }
        printf("\n");
    }
    return 0;

    // OLD STUFF
#if 0
    char stack[2048];
    for (int i = 0; i < sizeof(stack); i++) {
        stack[i] = 'a'+i%(1+'z'-'a');
    }
    stack[sizeof(stack)-1] = '\0';
    printf("\tstack\t%p\n", stack);
    //for (int i = 0; i < sizeof(stack); i++) { putchar(stack[i]); }
    printf("\tstack e\t%p\t", stack+sizeof(stack));
    printf("\n");
    int pid = clone(child, stack+sizeof(stack), CLONE_VM|SIGCHLD, stack);
#endif

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
    return 0;
}
