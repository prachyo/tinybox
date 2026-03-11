#ifndef POLICY_H
#define POLICY_H

#include <sys/syscall.h>
#include <sys/types.h>
#include <stdlib.h>

#define MAX_SYSCALL 512

typedef enum {
    ACTION_DENY = 0,
    ACTION_ALLOW,
    ACTION_HOOK
} action_t;

typedef int (*syscall_handler_t)(pid_t child, struct user_regs_struct *regs);

typedef struct {
    action_t action;
    const char *name;
} syscall_entry_t;

extern syscall_entry_t syscall_policy[MAX_SYSCALL];
extern syscall_handler_t dispatch_table[MAX_SYSCALL];

void init_policy();
void register_syscall(int id, const char *name, action_t action, syscall_handler_t handler);
int is_on_allowlist(long long syscall_id);

#endif
