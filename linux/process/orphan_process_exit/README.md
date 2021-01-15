## 父进程退出时如何确保子进程退出
### 前言
子进程退出的时候，父进程能够收到子进程退出的信号，便于管理，但是有时候又需要在父进程退出的时候，子进程也退出，该怎么办呢？

### 父进程退出时，子进程会如何？
一般情况下，父进程退出后，是不会通知子进程的，这个时候子进程会成为孤儿进程，最终被init进程收养。我们先来看一下这种情况。
```c
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
```
在这个程序中，我们为了让父进程先退出，子进程sleep了10秒。
运行结果如下：
```bash
parent process.
child process.
child  pid:91029,parent pid:91028
sleep 10 seconds.
now child pid: 91029 parent pid:1
```
从结果中可以看到，一开始子进程91029的父进程id是91028，但是在10秒后，它的父进程变成了1。1是什么进程呢？
```
ls -al /proc/1/exe
/proc/1/exe -> /usr/lib/systemd/systemd
```

### 如何确保父进程退出的同时，子进程也退出？
既然如此，如何确保父进程退出的同时，子进程也退出呢？或许我们可以在子进程和父进程之间建立通信管道，一旦通信异常，则认为父进程退出，子进程自己也回收资源退出。但是这样做总觉得不是很正经。有没有已有的函数帮我们做这件事呢？prctl 函数可以帮助我们。第一个参数中，有一个选项，叫做PR_GET_PDEATHSIG:
```
PR_SET_PDEATHSIG (since Linux 2.1.57)
Set  the  parent  death signal of the calling process to arg2 (either a signal value in the range 1..maxsig, or 0 to clear).
This is the signal that the calling process will get when its parent dies.  This value is cleared for the child of a fork(2)
and (since Linux 2.4.36 / 2.6.23) when executing a set-user-ID or set-group-ID binary, or a binary that has associated capa‐bilities (see capabilities(7)).  This value is preserved across execve(2).
```
内容很多，主要意思为：设置一个信号，当父进程退出的时候，子进程将会收到该信号。
那么根据这个，我们完全可以在父进程退出时，也给子进程一个退出的信号。程序代码如下：
```c
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
```
运行结果：
```
parent process.
child process.
child  pid:17625,parent pid:17624
sleep 10 seconds.
```
可以看到，由于加入了`prctl(PR_SET_PDEATHSIG,SIGKILL);`，
在父进程退出时，子进程将会收到SIGKILL信号，而进程收到该信号的默认动作则是退出。因而最后不会看到它成为孤儿进程，被其他进程所收养。需要注意的是，该函数并非所有系统都支持。

总结
有些情况下，我们常常需要父子进程共存亡，子进程退出时，父进程可以通过wait捕捉子进程的退出状态，但是父进程退出时，子进程却难以得知。因此，在最初fork子进程的时候，便表明了，当父进程退出的时候，子进程收到SIGKILL信号，最终也退出。以此达到同生共死的目的。当然也可以发送其他信号，由子进程捕获该信号并做后续处理。