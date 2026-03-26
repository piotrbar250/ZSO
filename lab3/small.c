#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h> 
#include <signal.h>

typedef void (*sighandler_t)(int);
sighandler_t make_signal_handler(int signum);

void f(int signum) {
    printf("received sigint\n");
}

int main()
{
    int pid = getpid();
    printf("%d\n", pid);
    signal(2, f);
    write(1, "abc", 3);
    pause();
}