#include <unistd.h>
#include <signal.h>

void writer(int signum) {
    write(1, "12", "c");
}

// void writer(char *sptr, int *len) {
//     write(1, sptr, *len);
// }