/*************************************************************************************
作用：
定义向量的长度。

用法：
__attribute__((__vector_size__(n)))
**************************************************************************************/

#include <stdio.h>  
#include "ctype.h"
#include "inttypes.h"

//在32位机器中，就表示2个4字节（8）的向量
typedef uint8_t rte_v64u8_t __attribute__((vector_size(8), aligned(8)));

//在32位机器中，就表示4个4字节（8）的向量
typedef float v4si __attribute__((vector_size(16)));


int main(int argc, char * argv[]) {
    
    v4si aaa = {1.0,2.0,3.0,4.0};

    rte_v64u8_t bbb = {1,2};
    
    printf("sizeof(aaa) = %lu\n", sizeof(aaa));
    printf("sizeof(bbb) = %lu\n", sizeof(bbb));
    
    return 0;
}
