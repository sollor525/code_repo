/*****************************************************************************
可以给对类型、结构体（struct ）或共用体（union ）设置别名
*****************************************************************************/

#include <stdio.h>  
#include <ctype.h>  
#include <stdint.h>
   
typedef struct S {

    short b[3];

} __attribute__((__may_alias__)) short3_t_alias;

typedef uint16_t __attribute__((__may_alias__)) u16_p;



int main(void)
{
    short3_t_alias aaa;
    u16_p a_s = 11;
    
    aaa.b[0] = 1;
    aaa.b[1] = 2;
    aaa.b[2] = 3;
    
    printf("%d\n", aaa.b[1]);
    printf("%d\n", a_s);
    
    return 0;
}

