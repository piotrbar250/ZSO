#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>   /* mmap(), mprotect() */
#include <signal.h>
#include <malloc.h>

// static uint8_t code[] = {
//     0xB8,0xFF,0x00,0x00,0x00,   /* mov  eax,0xFF    */
//     0xC3,                       /* ret              */
// };

static uint8_t code[] = {
    0xF3,0x0F,0x1E,0xFA,
    0x55,
    0x48,0x89,0xE5,
    0x48,0x83,0xEC,0x10,
    0x89,0x7D,0xFC,
    0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x48,0x89,0xC2,
    0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x48,0x89,0xC6,
    0xBF,0x01,0x00,0x00,0x00,
    0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xFF,0xD0,
    0x90,
    0xC9,
    0xC3
};


typedef void (*sighandler_t)(int);
sighandler_t make_signal_handler(int signum)
{
    const size_t len = sizeof(code);

    /* mmap a region for our code */
    void *p = mmap(NULL, len, PROT_READ|PROT_WRITE,  /* No PROT_EXEC */
            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        fprintf(stderr, "mmap() failed\n");
        return SIG_ERR;
    }

    /* Copy it in (still not executable) */
    memcpy(p, code, len);

    char *numbuf = malloc(20); 
    snprintf(numbuf, 20, "%d", signum);
    size_t numbuf_len = strlen(numbuf);

    memcpy(p + 0x11, &numbuf_len, 8);

    memcpy(p + 0x1e, &numbuf, 8);

    void *write_addr = (void *)write;
    memcpy(p + 0x30, &write_addr, 8);

    /* Now make it execute-only */
    if (mprotect(p, len, PROT_EXEC) < 0) {
        fprintf(stderr, "mprotect failed to mark exec-only\n");
        return SIG_ERR;
    }

    return signal(signum, (sighandler_t)p);
}

int main(void)
{
    make_signal_handler(10);

    printf("PID: %d\n", getpid());
    for (;;) pause();

    return 0;
}
