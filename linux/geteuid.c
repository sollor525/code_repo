#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>



int main(char *argc, int argv)
{
    int fd;
    printf("uid study: \n");
    printf("Process's uid = %d, euid = %d\n", getuid(), geteuid());

    if( (fd = open("test.txt", O_RDWR | O_CREAT)) == -1 )
    {
        printf("Open failure, errno is %d :%s \n", errno, strerror(errno));
        exit(1);
    }
    else
    {
       printf("Open successfully!\n");
       close(fd);
    }
    exit(0);
}