#include <stdio.h>
#include <unistd.h>

int main() {
    sleep(30);  // Give debugger time to attach and set breakpoint
    int x = 42;
    int y = x + 8;
    printf("x = %d, y = %d\n", x, y);
    return 0;
}
