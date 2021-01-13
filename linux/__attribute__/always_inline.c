/*************************************************************************************
内联函数:内联函数从源代码层看，有函数的结构，而在编译后，却不具备函数的性质。内联函数不是在调用时发生控制转移，而是在编译时将函数体嵌入在每一个调用处。编译时，类似宏替换，使用函数体替换调用处的函数名。一般在代码中用inline修饰，但是能否形成内联函数，需要看编译器对该函数定义的具体处理

noinline 不内联
always_inline 总是内联
这两个都是用在函数上
内联的本质是用代码块直接替换掉函数调用处,好处是:快代码的执行，减少系统开销.适用场景:
这个函数更小
这个函数不被经常调用

和 static inline定义函数的区别：
如果只定义内联的话，编译器并不一定会以内联的方式调用。如代码太多等情况。
且在gcc编译器中，如果编译优化设置为-O0，即使是inline函数也不会被内联展开。
使用了__attribute__((always_inline))能够保证代码是内联的。
**************************************************************************************/

#include <stdio.h> 


void static inline test(const char *s)  
{  
   printf("test : %s\n", s);  
}  

void static inline test(const char *s) __attribute__((always_inline));


void static inline __attribute__((always_inline)) test1 (const char *s)  
{  
   printf("test1 : %s\n", s);  
}  

int main(void)
{
    test("hahaha");
    test1("hahaha");
    return 0;
}