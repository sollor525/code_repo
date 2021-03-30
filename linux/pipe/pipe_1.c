
/*
这个程序创建了一个管道，并且对管道写了一个字符串之后从管道读取，并打印在标准输出上
*/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define STRING "hello world!"

int main()
{
    int pipefd[2];
    char buf[BUFSIZ];
    if (pipe(pipefd) == -1) {
        perror("pipe()");
        exit(1);
    }
    if (write(pipefd[1], STRING, strlen(STRING)) < 0) {
        perror("write()");
        exit(1);
    }
    if (read(pipefd[0], buf, BUFSIZ) < 0) {
        perror("write()");
        exit(1);
    }
    printf("%s\n", buf);
 
    exit(0);
}