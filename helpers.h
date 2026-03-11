#ifndef HELPERS_H
#define HELPERS_H

#include <sys/types.h>
#include <unistd.h>

ssize_t read_child_string(pid_t child, unsigned long addr, char *dest, size_t len);

#endif
