/*************************************************************************
	> File Name: execl_1.c
	> Author: 
	> Mail: 
	> Created Time: Tue 22 May 2018 08:08:14 PM CST
 ************************************************************************/

#include <stdio.h>
#include <unistd.h>
int main(void)
{
    printf("Executing ls\n");
    execl("/bin/ls","ls","-l",NULL);
    /* 如果 execl 返回，说明调用失败 */
    perror("execl failed to run ls");
    //exit(1);
    return 0;
}
