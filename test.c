#include <stdio.h>
#include <unistd.h>

int main() {
    int x = 42;
    int y = x + 8;
    printf("x = %d, y = %d\n", x, y);
    sleep(10);  // Keep running so you can attach
    return 0;
}

