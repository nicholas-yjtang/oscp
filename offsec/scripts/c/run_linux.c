#include <stdio.h>
#include <stdlib.h>

int main  (int argc, char *argv[]) {
    int i;
#ifdef ACCEPT_ARGS
    if (argc > 1) {
        i = system(argv[1]);
    }
    else {
        i = system("{command}");
    }
#else
    i = system("{command}");
#endif
    return 0;
}