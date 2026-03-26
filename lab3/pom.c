#include <unistd.h>

void writer() {
    write(1, "abc", 3);
}

int main() {
    writer();
}