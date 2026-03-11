#define _GNU_SOURCE
#include "helpers.h"
#include <sys/uio.h>

ssize_t read_child_string(pid_t child, unsigned long addr, char *dest, size_t len) {
    struct iovec local[1];
    struct iovec remote[1];

    local[0].iov_base = dest;
    local[0].iov_len = len;
    remote[0].iov_base = (void *)addr;
    remote[0].iov_len = len;

    ssize_t nread = process_vm_readv(child, local, 1, remote, 1, 0);

    if (nread > 0 && nread < (ssize_t)len) {
        dest[nread] = '\0';
    } else if (nread >= (ssize_t)len) {
        dest[len - 1] = '\0';
    }

    return nread;
}
