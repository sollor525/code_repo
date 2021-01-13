/*************************************************************************************
功能：__attribute__ format属性可以给被声明的函数加上类似printf或者scanf的特征，
它可以使编译器检查函数声明和函数实际调用参数之间的格式化字符串是否匹配。
format属性告诉编译器，按照printf, scanf等标准C函数参数格式规则对该函数的参数进行检查。
这在我们自己封装调试信息的接口时非常的有用。

format的语法格式为：
format (archetype, string-index, first-to-check)
其中，"archetype"指定是哪种风格；
"string-index"指定传入函数的第几个参数是格式化字符串；
"first-to-check"指定从函数的第几个参数开始按上述规则进行检查。

具体的使用如下所示：
__attribute__((format(printf, a, b)))
__attribute__((format(scanf, a, b)))
　　其中参数m与n的含义为：
　　　　a：第几个参数为格式化字符串(format string);
　　　　b：参数集合中的第一个，即参数“…”里的第一个参数在函数参数总数排在第几。
**************************************************************************************/

#include <stdio.h>  
#include <stdarg.h>  



#if 1  
#define CHECK_FMT(a, b) __attribute__((format(printf, a, b)))  
#else  
#define CHECK_FMT(a, b)  
#endif  
  
void TRACE(const char *fmt, ...) CHECK_FMT(1, 2);  

void TRACE(const char *fmt, ...)  
{  
    va_list ap;  
    char string[256];
    
    va_start(ap, fmt);  
    
    vsprintf(string,fmt,ap);
    printf("[%s]%s", "debug", string);
    //(void)printf(fmt, ap);  
  
    va_end(ap);  
}  


int main(void)  
{  
    TRACE("iValue = %d\n", 6);  
    TRACE("iValue = %d\n", "abc");  
    return 0;  
}  
