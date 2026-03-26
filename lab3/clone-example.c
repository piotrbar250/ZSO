#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define STACK_SIZE 65536

int global_value = 0;
char *heap;

static int child_func(void *arg)
{
    char *buf = (char *)arg;

    printf("Child sees buf=%s\n", buf);
    printf("Child sees global value = %d\n", global_value);
    printf("Child sees heap = %s\n", heap);
    strcpy(buf, "Hello from Child");
    global_value = 10;
    strcpy(heap, "bye");
    return 0;
}

int main(int argc, char *argv[])
{
    char *stack = malloc(STACK_SIZE);
    unsigned long flags = 0;
    char buf[256];
    int status = 0;

    heap = malloc(1024);

    if (argc == 2 && !strcmp(argv[1], "vm"))
        flags |= CLONE_VM;
    
    strcpy(buf, "Hello from Parent");
    strcpy(heap, "Hey");
    global_value = 5;
    if (clone(child_func, stack + STACK_SIZE, flags | SIGCHLD, buf) == -1) {
        perror("clone");
        exit(1);
    }

    if (wait(&status) == -1) {
        perror("wait");
        exit(1);
    }

    printf("Child exited with status: %d\t", status);
    printf("buf: %s\t global value: %d \n", buf, global_value);
    printf("Parent heap: %s\n", heap);

    return 0;
}