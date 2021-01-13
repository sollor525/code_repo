/*************************************************************************************
函数前面使用这个扩展，表示该函数会被经常调用到，在编译链接时要对其优化，
或说是将它和其他同样热(hot)的函数放到一块，这样有利于缓存的存取。
**************************************************************************************/

#include <stdio.h> 


void static inline test(const char *s)  
{  
   printf("test : %s\n", s);  
}  

void static inline test(const char *s) __attribute__((hot));


void static inline __attribute__((hot)) test1 (const char *s)  
{  
   printf("test1 : %s\n", s);  
}  

int main(void)
{
    test("hahaha");
    test1("hahaha");
    return 0;
}