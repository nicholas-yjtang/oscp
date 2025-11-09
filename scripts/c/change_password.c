#include <stdlib.h>

int main () {
    int i;    
    i = system("net user {username} {password}");
    return 0;
}