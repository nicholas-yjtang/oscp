#ifndef CURL_UTIL_H
#define CURL_UTIL_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

    struct MemoryStruct {             
      char *memory;                
    size_t size;
    };

    size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp);
    void curl_load_memory(char  * url, struct MemoryStruct *chunk);
    void curl_cleanup(struct MemoryStruct *chunk);

#ifdef __cplusplus
}
#endif

#endif /* CURL_UTIL_H */