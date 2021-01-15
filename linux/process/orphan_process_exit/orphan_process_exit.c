/******************************************************************************************************
父进程退出时，使子进程同步退出，而不成为一个孤儿进程。
使用：
prctl(PR_SET_PDEATHSIG,SIGKILL);
也可以发送别的信号。
******************************************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <signal.h>
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
        /*父进程退出时，会收到SIGKILL信号*/
        prctl(PR_SET_PDEATHSIG,SIGKILL);
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