/*************************************************************************************
作用：
表示该函数或变量可能不使用，这个属性可以避免编译器产生警告信息。

用法：
__attribute__((__unused__))
**************************************************************************************/

#include <stdio.h>  

__attribute__((unused))
void common_print(const char *s) 
{   
    int __attribute__((__unused__)) i=0;
    
    printf("common_print : %s\n",s);  
}    

__attribute__((used))
void common_print1(const char *s) 
{   
    int __attribute__((used)) i=0;
    printf("common_print : %s\n",s);  
}    


int main(int argc, char *argv[])  
{  
    printf("I want to test gcc attribute");  
    return 0;  
}  