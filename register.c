#include <stdio.h>

unsigned long stack_pointer = 5;
int main() {
    
    // This tells the compiler to grab the x86 stack pointer register (rsp)
    // and put its value into our C variable.
    __asm__("mov %%rsp, %0" : "=r" (stack_pointer));
    
    printf("The current stack pointer is at memory address: 0x%lx\n", stack_pointer);
    return 0;
}