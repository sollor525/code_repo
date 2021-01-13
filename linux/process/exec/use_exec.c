/******************************************************************************************************
加载可执行文件映像

#include <unistd.h>
int execl(const char *path,const char *arg,...);                     //  l表示命令行参数为以0结束的多个字符串组成 ，v表示命令行参数为以0结束的字符串数组组成
int execle(const char *path,const char *arg,...,char *const envp[]);  //e表示指定环境表量，原来的环境变量不起作用
int execlp(const char *file,const char *arg,...);                      //p表示可执行映像文件在环境变量path路径中查找
int execv(cosnt char *path,char *const argv[]);
int execve(const char *path,char *const argv[],char *const envp[]);
int execvp(const char *file,char *const argv[]);
path 代表可执行文件路径，arg代表命令行参数
******************************************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main()
{
    char *nenv[]={"NAME=value","NEXT=nextvale",(char*)0};
    char *nargv[]={"testexec","param1","param2",(char *)0}; //命令行参数都以0结尾
    pid_t pid;
    pid=fork();
    switch(pid)
    {
        case 0:           
            execve("./test_exec",nargv,nenv);      //指定环境变量，原来的环境变量不起作用
            //execl("./test_exec","testexec",0);  //不指定环境表量
            perror("exec");
            exit(1);
        case -1:
            perror("fork");
            exit(1);
        default:
            wait(NULL);
            printf("exec is completed\n");
            exit(0);
    }
}