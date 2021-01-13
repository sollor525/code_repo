/*************************************************************************
> File Name: execlp_1.c
> Author: 
> Mail: 
> Created Time: Wed 23 May 2018 05:20:35 PM CST
************************************************************************/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


char command[256];


int main()
{
    int rtn = 0; /*子进程的返回数值*/
    while(1)
    {
        /* 从终端读取要执行的命令 */
        printf( ">"  );
        fgets( command, 256, stdin  );
        command[strlen(command)-1] = 0;
        printf("%s\n", &command);
        if ( fork() == 0  ) 
        {
            /* 子进程执行此命令 */
            execl( command, NULL  );
            /* 如果exec函数返回，表明没有正常执行命令，打印错误信息*/
            perror( command  );
            exit( errno  );
        }
        else 
        {
            /* 父进程， 等待子进程结束，并打印子进程的返回值 */
            wait ( &rtn  );
            printf( " child process return %d\n", rtn  );
        }

    }
    return 0;
}
