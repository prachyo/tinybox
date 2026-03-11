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

int main(int argc, char *argv[]) {

    if (argc < 2) {
        fprintf(stderr,"Usage: %s <file>\n", argv[0]);
        exit(1);
    }

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

        while(1) {
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            waitpid(pid, &status, 0);

            if (WIFEXITED(status) || WIFSIGNALED(status)) break;

            if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
                if (on_enter) {
                    struct user_regs_struct regs;
                    struct iovec iov;
                    iov.iov_base = &regs;
                    iov.iov_len = sizeof(regs);
                    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) < 0) {
                        perror("ptrace(GETREGSET)");
                        break;
                    }
                    printf("tinybox: Syscall %llu\n", regs.orig_rax);

                    on_enter = 0;
                } else {
                    on_enter = 1;
                }
            }
        }

        printf("tinybox: Child finished execution.\n");
    }

    return 0;
}
