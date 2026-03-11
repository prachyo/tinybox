#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main() {
    const char *filename = "sandbox_test.txt";
    const char *msg = "Data inside the jail.\n";
    char buffer[64];

    int fd = open(filename, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) {
        perror("GOOD_TEST: Failed to open local file");
        return 1;
    }

    write(fd, msg, strlen(msg));
    lseek(fd, 0, SEEK_SET);
    read(fd, buffer, strlen(msg));

    printf("GOOD_TEST: Read from file: %s", buffer);

    close(fd);
    unlink(filename);
    return 0;
}
