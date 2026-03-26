// try_lstar.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <stdlib.h>
#include <ucontext.h>
#include <string.h>

// #ifndef REG_RIP
// #define REG_RIP 16   // x86-64 glibc/ucontext index
// #endif

// static void handler(int sig, siginfo_t *si, void *ctx_void) {
//     ucontext_t *ctx = (ucontext_t *)ctx_void;

//     printf("Caught signal %d (%s)\n", sig, strsignal(sig));
//     printf("si_code = %d\n", si->si_code);

// #ifdef __x86_64__
//     printf("Faulting RIP = 0x%llx\n",
//            (unsigned long long)ctx->uc_mcontext.gregs[REG_RIP]);
// #endif

//     exit(0);
// }

int main(void) {
    // struct sigaction sa;
    // memset(&sa, 0, sizeof(sa));
    // sa.sa_sigaction = handler;
    // sa.sa_flags = SA_SIGINFO;

    // sigaction(SIGSEGV, &sa, NULL);
    // sigaction(SIGILL,  &sa, NULL);
    // sigaction(SIGBUS,  &sa, NULL);

    // IA32_LSTAR MSR number on x86-64
    uint32_t msr = 0xC0000082;

    // Dummy "malicious" target address just for demonstration
    uint64_t new_value = 0x123456789ABCDEF0ULL;

    uint32_t low  = (uint32_t)(new_value & 0xffffffffu);
    uint32_t high = (uint32_t)(new_value >> 32);

    printf("About to try WRMSR to IA32_LSTAR (MSR 0x%x)\n", msr);
    printf("Attempted value = 0x%016llx\n", (unsigned long long)new_value);

    // This should fault in user mode.
    __asm__ volatile (
        "wrmsr"
        :
        : "c"(msr), "a"(low), "d"(high)
        : "memory"
    );

    // You should never get here in normal user mode.
    printf("WRMSR unexpectedly succeeded.\n");
    return 0;
}