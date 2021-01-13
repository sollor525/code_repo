/*************************************************************************************
函数前面使用这个扩展，表示该函数比较冷门，这样在分支预测机制里就不会对该函数进行预取，
或说是将它和其他同样冷门(cold)的函数放到一块，这样它就很可能不会被放到缓存中来，而让更热门的指令放到缓存中。
**************************************************************************************/

#include <stdio.h> 


void static inline test(const char *s)  
{  
   printf("test : %s\n", s);  
}  

void static inline test(const char *s) __attribute__((cold));


void static inline __attribute__((cold)) test1 (const char *s)  
{  
   printf("test1 : %s\n", s);  
}  

int main(void)
{
    test("hahaha");
    test1("hahaha");
    return 0;
}