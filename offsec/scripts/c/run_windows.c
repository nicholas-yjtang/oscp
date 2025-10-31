#include <stdlib.h>

int main (int argc, char *argv[]) {
    int i;    
#ifdef ACCEPT_ARGS
    if (argc > 1) {
        i = system(argv[1]);
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