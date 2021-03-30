//pipe_parent_child2.c
/*
父进程关闭管道的读端，只写管道。子进程关闭管道的写端，只读管道。
此时两个进程就只用管道实现了一个单工通信，并且这种状态下不用考虑多个进程同时对管道写产生的数据交叉的问题，
这是最经典的管道打开方式，也是我们推荐的管道使用方式。
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
        close(pipefd[1]);
        printf("Child pid is: %d\n", getpid());
        if (read(pipefd[0], buf, BUFSIZ) < 0) {
            perror("write()");
            exit(1);
       }
        printf("%s\n", buf);
 
    } else {
        /* this is parent */
        close(pipefd[0]);
        printf("Parent pid is: %d\n", getpid());
        snprintf(buf, BUFSIZ, "Message from parent: My pid is: %d", getpid());
        if (write(pipefd[1], buf, strlen(buf)) < 0) {
            perror("write()");
            exit(1);
        }
        wait(NULL);
    }
    exit(0);
}