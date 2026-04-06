#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void encode(void *buf, size_t size) {
    #ifdef ENCODING_XOR
    int key = {KEY};
    for (size_t i = 0; i < size; i++) {
        ((char *)buf)[i] ^= key;
    }
    #endif
}

int main (int argc, char *argv[])
{
    if (argc !=3) {
        printf("Usage: %s <file_in> <file_out>\n", argv[0]);
        return 0;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    void *buf = malloc(size);
    fread(buf, 1, size, f);
    fclose(f);
    encode(buf, size);
    FILE *out = fopen(argv[2], "wb");
    if (!out) {
        perror("fopen");
        free(buf);
        return 1;
    }
    fwrite(buf, 1, size, out);
    fclose(out);
    free(buf);
    return 0;
}
