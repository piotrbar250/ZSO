#include <sys/time.h>
#include <stdio.h>

int main()
{
    struct timeval tv;
    printf("123\n");
    gettimeofday(&tv, NULL);
    printf("%ld\n", tv.tv_sec);
}