/*************************************************************************************
作用：对函数的优化/禁止优化。

用法：
__attribute__((optimize("O0")))  
**************************************************************************************/
#include "stdio.h"

int  __attribute__((optimize("O0"))) add(int x)
{
    printf("%s(%d)\n", __FUNCTION__, x);
    return x + 1;
}
 
 
int main(int argc, char* argv[])
{
    int i, j;
 
    i = add(10);
    j = add(10);
 
    printf("%d %d\n", i, j);
 
    return 0;
}

