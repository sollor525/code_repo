/*************************************************************************************
功能：__attribute__((deprecated)) 使编译会给出过时的警告。

用法：
__attribute__((deprecated))
__attribute__((deprecated(s)))
**************************************************************************************/

#include "stdio.h"

__attribute__((deprecated))
void hello() 
{
    printf("hello deprecated\n");
}


__attribute__((deprecated("deprecated infomation")))
void hello1() 
{
    printf("hello deprecated with infomation\n");
}


int main(int argc, char * argv[]) 
{
    hello();
    hello1();
    return 0;
}
