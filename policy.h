#include <sys/syscall.h>

#define MAX_SYSCALL 512

static char allow_list[MAX_SYSCALL] = {0};

void init_allowlist() {
    allow_list[SYS_read] = 1;
    allow_list[SYS_write] = 1;
    allow_list[SYS_exit_group] = 1;
    allow_list[SYS_brk] = 1;
    allow_list[SYS_mmap] = 1;
    allow_list[SYS_munmap] = 1;
    allow_list[SYS_rt_sigreturn] = 1;
}
