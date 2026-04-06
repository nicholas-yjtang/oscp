#include "curl_util.h"
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
 
  char *ptr = (char *)realloc(mem->memory, mem->size + realsize + 1);
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

void curl_load_memory(char  * url, struct MemoryStruct *chunk) {
    
  CURL *curl_handle;
  CURLcode res;

  chunk->memory = (char *)malloc(1);  /* will be grown as needed by the realloc above */
  chunk->size = 0;            /* no data at this point */

  curl_global_init(CURL_GLOBAL_ALL);

  curl_handle = curl_easy_init();

  curl_easy_setopt(curl_handle, CURLOPT_URL, url);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)chunk);

  res = curl_easy_perform(curl_handle);

  if(res != CURLE_OK) {
    fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
  }
  curl_easy_cleanup(curl_handle);

}

void curl_cleanup(struct MemoryStruct *chunk) {
    free(chunk->memory);
    curl_global_cleanup();
}
