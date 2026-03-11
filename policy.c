#include "policy.h"
#include "helpers.h"

#include <sys/reg.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <string.h>
#include <stdio.h>
#include <linux/limits.h> // For PATH_MAX

#define _GNU_SOURCE // Required for process_vm_readv

syscall_entry_t syscall_policy[MAX_SYSCALL];
syscall_handler_t dispatch_table[MAX_SYSCALL];

// -- HANDLERS  --
int handle_openat(pid_t child, struct user_regs_struct *regs) {

    char path[PATH_MAX];
    unsigned long path_addr = regs->rsi;

    ssize_t bytes_read = read_child_string(child, path_addr, path, sizeof(path));

    if (bytes_read <= 0) {
        fprintf(stderr, "tinybox: [ERROR] Failed to read path from child memory.\n");
        return -1;
    }

    if (strstr(path, "..") != NULL) {
        printf("Tinybox: [DENY] Blocked path traversal attempt: %s\n", path);
        return -1;
    }

    if (strncmp(path, "/lib", 4) == 0 || strncmp(path, "/usr/lib", 8) == 0) {
        return 0;
    }

    if (path[0] == '/') {
        printf("Tinybox: [DENY] Blocked absolute path access: %s\n", path);
        return -1;
    }

    printf("Tinybox: [ALLOW] Opening file: %s\n", path);
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

    // hook syscalls
    register_syscall(SYS_openat, "openat", ACTION_HOOK, handle_openat);
    register_syscall(SYS_open, "open", ACTION_HOOK, handle_openat);
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
