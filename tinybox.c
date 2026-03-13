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
#include <sys/resource.h>

#include "policy.h"
#include "helpers.h"

int main(int argc, char *argv[]) {
    int opt;
    int time_limit_s = 10;
    int mem_limit_mb = 64;

    while ((opt = getopt(argc, argv, "t:m:")) != -1) {
        switch (opt) {
            case 't':
                time_limit_s = atoi(optarg);
                break;
            case 'm':
                mem_limit_mb = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s [-t time_s] [-m mem_mb] <program> [args...]\n", argv[0]);
                exit(1);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Expected program names\n");
        exit(1);
    }

    char *target_prog = argv[optind];
    char **target_args = &argv[optind];

    init_policy();

    pid_t pid = fork();
    if (pid == 0) {
        // CHILD PROCESS

        struct rlimit mem_limit;
        mem_limit.rlim_cur = mem_limit_mb * 1024 * 1024; // 64mb mem limit
        mem_limit.rlim_max = mem_limit_mb * 1024 * 1024;
        setrlimit(RLIMIT_AS, &mem_limit);

        struct rlimit cpu_limit;
        cpu_limit.rlim_cur = time_limit_s;
        cpu_limit.rlim_max = time_limit_s;
        setrlimit(RLIMIT_CPU, &cpu_limit);

        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        execvp(target_prog, target_args);
        exit(1);

    } else {
        // PARENT PROCESS
        int status;
        waitpid(pid, &status, 0);

        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

        printf("tinybox: Monitoring started for PID %d\n", pid);

        int on_enter = 1;
        int is_blocked = 0;

        signal(SIGALRM, TLE_handler);
        alarm(time_limit_s + 1);

        while(1) {
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            waitpid(pid, &status, 0);

            if (WIFEXITED(status)) {
                printf("tinybox: [EXIT] process finished execution (Exit: %d)\n", WEXITSTATUS(status));
                break;
            }

            if (WIFSIGNALED(status)) {
                int sig = WTERMSIG(status);
                if (sig == SIGXCPU) TLE_handler(sig);
                else if (sig == SIGSEGV || sig == SIGABRT) MLE_handler(sig);
                else printf("tinybox: [TERM] process killed by signal %d\n", sig);
                break;

            }

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
