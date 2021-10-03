#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#define SYS_encrypt 447

int main(int argc, const char * argv[]){

char * a = "hello";
int key=2;
//syscall(SYS_encrypt, a, key);
syscall(SYS_encrypt, argv[1], argc);
printf("%d\n",SYS_write);

return 0;

}
