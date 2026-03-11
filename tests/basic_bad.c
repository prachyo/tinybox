#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    printf("BAD_TEST: Attempting to snooping on /etc/passwd...\n");

    int fd = open("/etc/passwd", O_RDONLY);

    if (fd < 0) {
        // If errno is EPERM or if the syscall was spoofed to -1 (ENOSYS)
        printf("BAD_TEST SUCCESS: Access was blocked as expected.\n");
        return 0;
    } else {
        printf("BAD_TEST FAILED: I actually opened /etc/passwd! Sandbox is broken.\n");
        close(fd);
        return 1;
    }
}
