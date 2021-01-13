/*************************************************************************
	> File Name: fork1.c
	> Author: 
	> Mail: 
	> Created Time: Tue 22 May 2018 05:18:36 PM CST
 ************************************************************************/

#include <stdio.h>
#include <unistd.h>
int main(void)
{
    pid_t pid;
    printf("Now only one process\n");
    printf("Calling fork… \n");
    pid=fork();
    if (!pid)
            printf("I’m the child\n");
        else if (pid>0)
            printf("I’m the parent, child has pid %d\n",pid);
        else
            printf("Fork fail!\n");
        return 0;

}

