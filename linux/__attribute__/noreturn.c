/*******************************************************************************
__attribute__ noreturn    表示没有返回值
这个属性告诉编译器函数不会返回，这可以用来抑制关于未达到代码路径的错误。 

C库函数abort（）和exit（）都使用此属性声明：
extern void exit(int)   __attribute__((noreturn));
extern void abort(void) __attribute__((noreturn));

其实这个属性感觉没鸟用。用的不好，如下面两个例子还会报错。
*******************************************************************************/

extern void exitnow();
//extern void exitnow() __attribute__((noreturn));

int foo(int n)
{
    if ( n > 0 )
    {
        exitnow();
    }
    else
        return 0;
}


void foo1(void) __attribute__ ((noreturn));
void foo1(void)
{
    asm volatile ("nop");
}



extern void foo3(void) { };
void foo2(void) __attribute__ ((noreturn));
 
void foo2(void)
{
    foo3();
}