#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <elf.h>
#include <sys/wait.h>
#include <errno.h>

#include "policy.h"

int main(int argc, char *argv[]) {

    if (argc < 2) {
        fprintf(stderr,"Usage: %s <file>\n", argv[0]);
        exit(1);
    }

    init_policy();

    pid_t pid = fork();
    if (pid == 0) {
        // CHILD PROCESS
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        execvp(argv[1], &argv[1]);

        perror("execvp");
        exit(1);

    } else {
        // PARENT PROCESS
        int status;
        waitpid(pid, &status, 0);

        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

        printf("tinybox: Monitoring started for PID %d\n", pid);

        int on_enter = 1;
        int is_blocked = 0;

        while(1) {
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            waitpid(pid, &status, 0);

            if (WIFEXITED(status) || WIFSIGNALED(status)) break;

            if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
                struct user_regs_struct regs;
                struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };

                if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) < 0) break;

                if (on_enter) {
                    long long syscall_id = regs.orig_rax;
                    int allowed = 0;

                    if (syscall_id < MAX_SYSCALL && dispatch_table[syscall_id] != NULL) {
                        allowed = (dispatch_table[syscall_id](pid, &regs) == 0);
                    } else {
                        allowed = is_on_allowlist(syscall_id);
                    }

                    static int exec_count = 0;
                    if (syscall_id == SYS_execve && exec_count == 0) {
                        allowed = 1;
                        exec_count++;
                    }

                    if (!allowed) {
                        const char *name = (syscall_id >= 0 && syscall_id < MAX_SYSCALL && syscall_policy[syscall_id].name)
                                                                   ? syscall_policy[syscall_id].name : "forbidden";

                        printf("tinybox: [BLOCK] %s (ID: %lld)\n", name, syscall_id);

                        regs.orig_rax = SYS_getpid;
                        ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov);
                        is_blocked = 1;
                    }

                    on_enter = 0;
                } else {
                    if (is_blocked) {
                        regs.rax = -EACCES;
                        ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov);
                        is_blocked = 0;
                    }
                    on_enter = 1;
                }
            }
        }

        printf("tinybox: Child finished execution.\n");
    }

    return 0;
}
