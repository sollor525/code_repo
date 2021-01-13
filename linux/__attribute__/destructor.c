/*************************************************************************************
功能：__attribute__((destructor)) 析构器。destructor修饰的函数会在程序exit前调用。

用法：
__attribute__((destructor))
__attribute__((destructor(PRIORITY)))
PRIORITY 为优先级。优先级[0,100]这个是系统保留的,不能调用。数值越大越先调用。
**************************************************************************************/

#include <stdio.h>  

__attribute__((constructor(101)))
void  before1()
{
    printf("before1 constructor(101)\n");
}


void __attribute__((constructor(102))) before2() 
{
    printf("before2 constructor(102)\n");
}


void before3() __attribute__((constructor));
void before3()
{
    printf("before3 constructor\n");
}


__attribute__((destructor(201)))
void  after1(){
    printf("after1 destructor(201)\n");
}



void __attribute__((destructor(202))) after2() 
{
    printf("after2 destructor(202)\n");
}

__attribute__((destructor))
void after3() 
{
    printf("after3 destructor\n");
}


int main(int argc, char * argv[]) 
{
    printf("main\n");
    return 0;
}
