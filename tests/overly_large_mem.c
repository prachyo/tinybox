#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    size_t size = 128 * 1024 * 1024; // 128MB
    char *ptr = (char *)malloc(size);

    if (ptr == NULL) {
        printf("Malloc failed as expected.\n");
        return 0;
    }
    memset(ptr, 1, size);

    printf("Successfully touched memory (This should not happen!)\n");
    return 1;
}
