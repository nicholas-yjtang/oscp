#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define ACCEPT_ARGS
#define MAX_COMMAND_LENGTH 1024
int main (int argc, char *argv[]) {
    int i;    
#ifdef ACCEPT_ARGS
    if (argc > 1 && strcmp(argv[1], "exec.command") == 0) {
        char command[MAX_COMMAND_LENGTH] = "";
        int command_len = 0;
        for (int j = 2; j < argc; j++) {
            strcat(command, argv[j]);
            strcat(command, " ");
            command_len += strlen(argv[j]) + 1;
        }
        if (command_len > MAX_COMMAND_LENGTH) {
            printf("Command length exceeds maximum limit with %d characters.\n", command_len);
            return 1;
        }
        i = system(command);
    }
    else {
    #ifdef RUN_BACKGROUND
        i = system("START /B {command}");
    #else
        i = system("{command}");
    #endif
    }
#else
    #ifdef RUN_BACKGROUND
        i = system("START /B {command}");
    #else
        i = system("{command}");
    #endif
#endif
    return 0;
}