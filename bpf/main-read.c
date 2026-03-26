#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    int file = open("in.txt", O_RDONLY);
    // printf("%d\n", file);
    char buf[21];
    int r = read(file, buf, 20);
    printf("%d\n", r);
    // close(file);
    while(1) {
        sleep(20);
    }
}