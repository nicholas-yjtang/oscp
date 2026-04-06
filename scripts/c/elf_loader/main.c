#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include "elf.h"

struct MemoryStruct {             
  char *memory;                
  size_t size;
};

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
 
  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(!ptr) {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
 
  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}

static void curl_load_memory(char  * url, struct MemoryStruct *chunk) {
    
   CURL *curl_handle;
   CURLcode res;

   chunk->memory = malloc(1);  /* will be grown as needed by the realloc above */
   chunk->size = 0;            /* no data at this point */

   curl_global_init(CURL_GLOBAL_ALL);

   curl_handle = curl_easy_init();

   curl_easy_setopt(curl_handle, CURLOPT_URL, url);
   curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_cb);
   curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)chunk);

   res = curl_easy_perform(curl_handle);

   if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
   } else {
        printf("%s\n", chunk->memory);
    }

    curl_easy_cleanup(curl_handle);

}

void curl_cleanup(struct MemoryStruct *chunk) {
    free(chunk->memory);
    curl_global_cleanup();
}

int main(int argc, char *argv[], char *envp[])
{
   if (argc != 2) {
      fprintf(stderr, "Usage: %s <url>\n", argv[0]);
      return 1;
   }
   struct MemoryStruct chunk;
   curl_load_memory(argv[1], &chunk);
   int size = chunk.size;


   char *_argv[] = {
      argv[0],
      "arg1",
      "arg2",
      NULL,
   };

   char *_env[] = {
      "HOME=/tmp",
      NULL,
   };

   printf("main: %p\n", elf_get_symbol(chunk.memory, "main"));

   // Run the ELF
   elf_run(chunk.memory, argv, envp);
   curl_cleanup(&chunk);
   return 0;
}

