//pipe_parent_child.c
/*
fork产生的子进程会继承父进程对应的文件描述符。
利用这个特性，父进程先pipe创建管道之后，子进程也会得到同一个管道的读写文件描述符。
从而实现了父子两个进程使用一个管道可以完成半双工通信。

此时，父进程可以通过fd[1]给子进程发消息，子进程通过fd[0]读。
子进程也可以通过fd[1]给父进程发消息，父进程用fd[0]读。
*/


#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#define STRING "hello world!"
 
int main()
{
    int pipefd[2];
    pid_t pid;
    char buf[BUFSIZ];
    if (pipe(pipefd) == -1) {
        perror("pipe()");
        exit(1);
    }
    pid = fork();
    if (pid == -1) {
        perror("fork()");
        exit(1);
    }
    if (pid == 0) {
        /* this is child. */
        printf("Child pid is: %d\n", getpid());
        if (read(pipefd[0], buf, BUFSIZ) < 0) {
            perror("write()");
            exit(1);
        }
        printf("%s\n", buf);
        bzero(buf, BUFSIZ);
        snprintf(buf, BUFSIZ, "Message from child: My pid is: %d", getpid());
        if (write(pipefd[1], buf, strlen(buf)) < 0) {
            perror("write()");
            exit(1);
        }
    } else {
        /* this is parent */
       printf("Parent pid is: %d\n", getpid());
        snprintf(buf, BUFSIZ, "Message from parent: My pid is: %d", getpid());
        if (write(pipefd[1], buf, strlen(buf)) < 0) {
            perror("write()");
            exit(1);
        }
        sleep(1);
        bzero(buf, BUFSIZ);
        if (read(pipefd[0], buf, BUFSIZ) < 0) {
            perror("write()");
            exit(1);
        }
        printf("%s\n", buf);
        wait(NULL);
    }
    exit(0);
}