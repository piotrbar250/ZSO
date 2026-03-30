#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
// #include <errno.h>

int main() {
    char buffer[5];
    size_t bytes_read;
    int fd = open("file", O_RDONLY);

    bytes_read = read(fd, buffer, sizeof(buffer) -1);
    buffer[bytes_read] = '\0';
    printf("bytes_read: %ld\n", bytes_read);
    printf("%s\n", buffer);
    
    
    lseek(fd, 3, SEEK_CUR);
    
    bytes_read = read(fd, buffer, sizeof(buffer) -1);
    buffer[bytes_read] = '\0';
    printf("bytes_read: %ld\n", bytes_read);
    printf("%s\n", buffer);
}