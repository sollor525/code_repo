//被调用程序
#include <stdio.h>

int glob=18;
extern char **environ;

int main(int argc,char *argv[])
{
    int local=20;
    int k;
    char **ptr=environ;
    glob++;
    local++;
    printf("&glob=%p,&local=%p\n",&glob,&local); //打印变量的地址
    printf("argc=%d\n",argc);
    for(k=0;k<argc;++k)
    {
        printf("argv[%d]\t %s\n",k,argv[k]);  //打印命令行参数
    }
    for(ptr=environ;*ptr!=0;++ptr) 
    {
       printf("%s\n",*ptr);              //打印环境变量
    }
    return 0;
}