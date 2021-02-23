#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/shm.h>
#include <sys/resource.h>
#include <time.h>
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

struct exec_child_arg {
    const char *dna;
    int shm_id;
};

void exec_child(void *arg) {
    // We do not wait to PTRACE this child because on exec it triggers SIGCHLD
    // with code CLD_TRAPPED which we catch and handle
    fprintf(stderr, "Dome child setting up PTRACE\n");
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        PRINTERRNO(ptrace);
        exit(-CHILD_ERR_PTRACE);
    }

    struct exec_child_arg *p = arg;
    char shm_id[12];
    sprintf(shm_id, "%d", p->shm_id);

    // Must send shmem_id and use shmat in the child. Maybe in a future version
    // we can make it through ptrace! (and seccomp as well!)
    fprintf(stderr, "Dome child going to exec '%s': %s %s\n", p->dna, "alpha", shm_id);
    execl(p->dna, "alpha", shm_id, (char *)NULL);

    PRINTERRNO(execl);
    exit(-CHILD_ERR_EXEC);
}

enum mmap_region {
    mmap_region_vvar,
    mmap_region_vdso,
    mmap_region_stack,
    mmap_region_file,
    // The following are unlikely, but who knows...
    mmap_region_heap,
    mmap_region_anon,
    mmap_region_unknown,
};

struct mmap {
    unsigned int begin, end;
    unsigned int file_offset;
    unsigned int dev_major, dev_minor;
    unsigned int inode;
    char read_flag, write_flag, exec_flag, private_flag;
    enum mmap_region region;
};

int read_mmap_line(FILE *map_file, struct mmap *map) {
    char *pathname;
    int assigns = fscanf(map_file, "%x-%x %c%c%c%c %x %x:%x %u %ms\n", &map->begin, &map->end,
           &map->read_flag, &map->write_flag, &map->exec_flag, &map->private_flag,
           &map->file_offset, &map->dev_major, &map->dev_minor, &map->inode, &pathname);

    if (assigns == EOF)
        return EOF;
    if (assigns < 11) {
        PRINTERRNO(read_mmap_line);
        return assigns;
    }

    if (pathname[0] == '\0') {
        map->region = mmap_region_anon;
    } else if (pathname[0] != '[') {
        map->region = mmap_region_file;
    } else if (strcmp(pathname, "[vdso]") == 0) {
        map->region = mmap_region_vdso;
    } else if (strcmp(pathname, "[stack]") == 0) {
        map->region = mmap_region_stack;
    } else if (strcmp(pathname, "[vvar]") == 0) {
        map->region = mmap_region_vvar;
    } else if (strcmp(pathname, "[heap]") == 0) {
        map->region = mmap_region_heap;
    } else {
        map->region = mmap_region_unknown;
    }

    free(pathname);
    return 0;
}

int set_limits(pid_t pid, size_t ground_size) {
    char maps_fname[1+4+1+10+1+4+1]; // Assumes no more than 10 digits (for 2^32) are required
    snprintf(maps_fname, sizeof(maps_fname), "/proc/%d/maps", pid);

    fprintf(stderr, "Maps filename: %s\n", maps_fname);
    FILE *maps = fopen(maps_fname, "r");
    if (!maps) {
        PRINTERRNO(set_limits);
        return -1;
    }

    const size_t data_size = 0x0;
    const size_t cpu_limit = 1;
    size_t as_size = data_size + ground_size, stack_size = 0;

    struct mmap map;
    int read_res;
    while ((read_res = read_mmap_line(maps, &map)) == 0) {
        as_size += map.end - map.begin;
        if (map.region == mmap_region_stack)
            stack_size = map.end - map.begin;
    }

    if (read_res != EOF) {
        return -1;
    }

    if (!stack_size)
        stack_size = sysconf(_SC_PAGESIZE);

    struct rlimit limit;
    limit = (struct rlimit){ cpu_limit, cpu_limit };
    prlimit(pid, RLIMIT_CPU, &limit, NULL);
    fprintf(stderr, "Cpu limit: %zd\n", cpu_limit);

    limit = (struct rlimit) { as_size, as_size };
    prlimit(pid, RLIMIT_AS, &limit, NULL);
    fprintf(stderr, "Address space limit: %zd\n", as_size);

    limit = (struct rlimit) { data_size, data_size };
    prlimit(pid, RLIMIT_DATA, &limit, NULL);
    fprintf(stderr, "Data limit: %zd\n", data_size);

    limit = (struct rlimit) { stack_size, stack_size };
    prlimit(pid, RLIMIT_STACK, &limit, NULL);
    fprintf(stderr, "Stack limit: %zd\n", stack_size);
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
        //Does not return, but just in case
        exit(-CHILD_ERR_EXEC);
    }
    default: // Parent
        printf("Child pid: %d\n", child_pid);
    }
    return child_pid;
}

// Globals required due to signals :( but only as pointers to readonly data!
struct {
    const int *shm_id;
    const void *ground;
    const size_t *ground_size;
} g_dome;

void on_sigchld(int signal, siginfo_t *info, void *ctx) {
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
        if (!set_limits(info->si_pid, *g_dome.ground_size)) {
            // Kill TERM
        }
        ptrace(PTRACE_DETACH, info->si_pid, NULL, NULL);
        break;
    case CLD_CONTINUED:
        break;
    case CLD_STOPPED:
        printf("Child %d stopped by signal %d\n", info->si_pid, info->si_status);
        switch(info->si_status) {
        case SIGSTOP:
            if (!set_limits(info->si_pid, *g_dome.ground_size)) {
                // Kill TERM
            }
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

void cleanup_exit(int signal, siginfo_t *info, void *ctx) {
    if (g_dome.ground)
        shmdt(g_dome.ground);
    if (g_dome.shm_id)
        shmctl(*g_dome.shm_id, IPC_RMID, NULL);
    exit(0);
}

void setup_signals() {
    struct sigaction child_action;
    child_action.sa_sigaction = on_sigchld;
    sigemptyset(&child_action.sa_mask);
    child_action.sa_flags = SA_SIGINFO | SA_NOCLDWAIT;
    sigaction(SIGCHLD, &child_action, NULL);

    struct sigaction int_action;
    int_action.sa_sigaction = cleanup_exit;
    sigemptyset(&int_action.sa_mask);
    int_action.sa_flags = SA_SIGINFO;
    sigaction(SIGINT, &int_action, NULL);
}

int create_ground(size_t size) {
    key_t shm_key;
    int shm_id;
    do {
        shm_key = rand();
        shm_id = shmget(shm_key, size, IPC_CREAT | IPC_EXCL);
    } while(shm_id == -1 && errno == EEXIST);
    if (shm_id == -1) {
        PRINTERRNO(create_ground);
        exit(-1);
    }

    struct shmid_ds buf;
    buf.shm_perm.uid = 1000;
    buf.shm_perm.gid = 100;
    buf.shm_perm.mode = 0600;
    shmctl(shm_id, IPC_SET, &buf);

    //See man shmctl for SHM_LOCK (prevent swapping)
    return shm_id;
}

int main(int argc, char **argv) {
    memset(&g_dome, 0, sizeof(g_dome));
    srand(time(NULL));

    printf("Parent pid = %ld\n", getpid());

    int page_size = sysconf(_SC_PAGESIZE);
    fprintf(stderr, "Page size = %d\n", page_size);

    size_t ground_size = page_size*1024;
    g_dome.ground_size = &ground_size;

    // We need to setup_signals before create_ground to make sure any ^C is always properly handled
    setup_signals();

    int shm_id = create_ground(ground_size);
    g_dome.shm_id = &shm_id;

    void *ground = shmat(shm_id, NULL, 0);
    if (ground == (void*)-1) {
        perror("Failed to attach ground");
        exit(-1);
    }
    g_dome.ground = ground;

    for (int i = 0; i < ground_size / sizeof(int); i++) {
        ((int *)ground)[i] = (rand()%100)+(i+1)*100;
    }

    pid_t pid = create_child(argv[1], shm_id);
    while(1) {
        sleep(1);
    }
    return 0;
}
