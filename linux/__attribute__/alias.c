/*****************************************************************************
可以给函数声明别名
*****************************************************************************/

#include <stdio.h>  
   
void __lib_print(const char *s)  
{  
   printf("__lib_print : %s\n", s);  
}  
   
void print_a(const char *s) __attribute__((alias("__lib_print")));  
void print_b(const char *s) __attribute__((alias("__lib_print")));  


int main(void)
{
    print_a("hahaha");
    print_b("hahaha");
    return 0;
}