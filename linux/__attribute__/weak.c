/*************************************************************************************
作用：
将本模块的函数声明为弱符号类型。
如果遇到强符号类型（即外部模块定义了func），那么我们在本模块执行的func将会是外部模块定义的func。
如果外部模块没有定义，那么，将会调用这个弱符号，也就是在本地定义的func。
相当于增加了一个默认函数。

原理：
连接器发现同时存在弱符号和强符号，有限选择强符号，如果发现不存在强符号，只存在弱符号，则选择弱符号。

用法：
__attribute__((weak)))  

注意:
weak属性只会在静态库(.o .a )中生效，动态库(.so)中不会生效。
**************************************************************************************/

#include <stdio.h>  

__attribute__((weak))
void common_print(const char *s) 
{  
    printf("weak common_print : %s\n",s);  
}    


//gcc -Wall weak.c weak_lib.c -o weak时，由于外部有common_print定义，所以调用weak_lib.c中的函数；
//gcc -Wall weak.c -o weak时，由于外部没有common_print定义，所以调用本文件中属性为weak的函数；
int main(int argc, char *argv[])  
{  
    common_print("I want to test gcc weak attribute");  
    return 0;  
}  

