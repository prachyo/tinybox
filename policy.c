#include "policy.h"
#include "helpers.h"

#include <sys/reg.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <string.h>
#include <stdio.h>
#include <linux/limits.h>

#define _GNU_SOURCE

syscall_entry_t syscall_policy[MAX_SYSCALL];
syscall_handler_t dispatch_table[MAX_SYSCALL];

// -- HANDLERS
int handle_unlink(pid_t child, struct user_regs_struct *regs) {
    char path[PATH_MAX];
    if (read_child_string(child, regs->rdi, path, sizeof(path)) <= 0) return -1;

    if (path[0] == '/' || strstr(path, "..")) {
        printf("tinybox: [SECURITY] Blocked attempt to delete: %s\n", path);
        return -1;
    }

    return 0;
}

int handle_openat(pid_t child, struct user_regs_struct *regs) {
    char path[PATH_MAX];
    if (read_child_string(child, regs->rsi, path, sizeof(path)) <= 0) {
        return -1;
    }

    if (strcmp(path, "/etc/ld.so.cache") == 0 ||
        strncmp(path, "/lib", 4) == 0 ||
        strncmp(path, "/usr/lib", 8) == 0) {
        return 0;
    }

    if (path[0] == '/') {
        printf("tinybox: [DENY] Absolute path: %s\n", path);
        return -1;
    }

    if (strstr(path, "..")) {
        printf("tinybox: [DENY] Traversal: %s\n", path);
        return -1;
    }

    return 0;
}

void register_syscall(int id, const char *name, action_t action, syscall_handler_t handler) {
    if (id < 0 || id >= MAX_SYSCALL) return;
    syscall_policy[id].name = name;
    syscall_policy[id].action = action;
    dispatch_table[id] = handler;
}

void init_policy() {
    for (int i = 0; i < MAX_SYSCALL; i++) {
        syscall_policy[i].action = ACTION_DENY;
        syscall_policy[i].name = "forbidden";
        dispatch_table[i] = NULL;
    }

    // always allow
    register_syscall(SYS_execve, "execve", ACTION_ALLOW, NULL);
    register_syscall(SYS_brk, "brk", ACTION_ALLOW, NULL);
    register_syscall(SYS_mmap, "mmap", ACTION_ALLOW, NULL);
    register_syscall(SYS_munmap, "munmap", ACTION_ALLOW, NULL);
    register_syscall(SYS_mprotect, "mprotect", ACTION_ALLOW, NULL);
    register_syscall(SYS_arch_prctl, "arch_prctl", ACTION_ALLOW, NULL);
    register_syscall(SYS_set_tid_address, "set_tid_address", ACTION_ALLOW, NULL);
    register_syscall(SYS_read, "read", ACTION_ALLOW, NULL);
    register_syscall(SYS_write, "write", ACTION_ALLOW, NULL);
    register_syscall(SYS_close, "close", ACTION_ALLOW, NULL);
    register_syscall(SYS_lseek, "lseek", ACTION_ALLOW, NULL);
    register_syscall(SYS_exit_group, "exit_group", ACTION_ALLOW, NULL);
    register_syscall(SYS_fstat, "fstat", ACTION_ALLOW, NULL);
    register_syscall(SYS_newfstatat, "newfstatat", ACTION_ALLOW, NULL);
    register_syscall(SYS_access, "access", ACTION_ALLOW, NULL);
    register_syscall(SYS_pread64, "pread64", ACTION_ALLOW, NULL);
    register_syscall(SYS_writev, "writev", ACTION_ALLOW, NULL);
    register_syscall(SYS_uname, "uname", ACTION_ALLOW, NULL);
    register_syscall(SYS_readlink, "readlink", ACTION_ALLOW, NULL);
    register_syscall(SYS_set_robust_list, "set_robust_list", ACTION_ALLOW, NULL);
    register_syscall(334, "rseq", ACTION_ALLOW, NULL); // couldn't find the enum value hmm..
    register_syscall(SYS_prlimit64, "prlimit64", ACTION_ALLOW, NULL);
    register_syscall(SYS_getrandom, "getrandom", ACTION_ALLOW, NULL);

    // hook syscalls
    register_syscall(SYS_openat, "openat", ACTION_HOOK, handle_openat);
    register_syscall(SYS_open, "open", ACTION_HOOK, handle_openat);
    register_syscall(SYS_unlink, "unlink", ACTION_HOOK, handle_unlink);
}

int is_on_allowlist(long long syscall_id) {
    if (syscall_id < 0 || syscall_id >= MAX_SYSCALL) {
        return 0;
    }

    if (syscall_policy[syscall_id].action == ACTION_ALLOW ||
        syscall_policy[syscall_id].action == ACTION_HOOK) {
        return 1;
    }

    return 0;
}
