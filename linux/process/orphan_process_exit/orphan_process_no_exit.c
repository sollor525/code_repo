/******************************************************************************************************
父进程退出时，子进程不退出，成为一个孤儿进程。
******************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

int main(void)
{
    pid_t pid;
    //fork一个进程
    pid = fork();
    //创建失败
    if (pid < 0)
    {
        perror("fork error:");
        exit(1);
    }
    //子进程
    if (pid == 0)
    {
        printf("child process.\n");
        printf("child  pid:%d,parent pid:%d\n",getpid(),getppid());
        printf("sleep 10 seconds.\n");
        //sleep一段时间，让父进程先退出，为了便于观察，sleep 10s
        sleep(10);

        printf("now child pid: %d parent pid:%d\n",getpid(),getppid());
    }
    //父进程
    else
    {
        printf("parent process.\n");
        sleep(1);
    }
    return 0;
}