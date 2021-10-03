#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
int main(void)  {
    struct timeval tv;
    int ret;
    ret = gettimeofday(&tv, NULL);
    if(ret == -1){
        perror("gettimeofday");
        return EXIT_FAILURE;
    }
    printf("Local time:\n")
    printf(" sec:%lu\n", tv.tv_sec)
    printf(" usec:%lu\n", tv.tv_usec)
    return EXIT_SUCCESS;
}
