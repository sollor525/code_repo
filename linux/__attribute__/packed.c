/*************************************************************************************
作用：
让指定的结构结构体按照一字节对齐。
aligned 属性使被设置的对象占用更多的空间，使用packed 可以减小对象占用的空间。

用法：
__attribute__((__packed__))) 

注意:
#pragma pack能够改变编译器的默认对齐方式
**************************************************************************************/

#include "stdio.h"


struct p {
    int a;
    char b;
    short c;
}__attribute__((aligned(4))) pp;

struct m {
    char a;
    int b;
    short c;
}__attribute__((aligned(4))) mm;

struct o {
    int a;
    char b;
    short c;
}oo;

struct x {
    int a;
    char b;
    struct p px;
    short c;
 }__attribute__((aligned(8))) xx;

struct MyStruct {
    char c;
    int  i;
    short s;
}__attribute__ ((__packed__));

struct MyStruct1 {
    char c;
    int  i;
    short s;
}__attribute__ ((aligned));

struct MyStruct2 {
    char c;
    int  i;
    short s;
}__attribute__ ((aligned(4)));

struct MyStruct3 {
    char c;
    int  i;
    short s;
}__attribute__ ((aligned(8)));

struct MyStruct4 {
    char c;
    int  i;
    short s;
}__attribute__ ((aligned(16)));

struct unpacked_struct {
    char c;
    int i;
};

struct packed_struct_1 {
    char c;
    int i;
} __attribute__((__packed__));

#pragma pack(2)
struct Test1 {
    char c1;
    short s;
    char c2;
    int i;
};
#pragma pack()

#pragma pack(4)
struct Test2 {
    char c1;
    char c2;
    short s;
    int i;
};
#pragma pack()


//内部的成员变量 us 不会被压缩，如果希望 us 也被压缩，则 struct unpacked_struct 也需要使用packed 进行相应的约束。
struct packed_struct_2 {
    char c;
    int i;
    struct unpacked_struct us;
} __attribute__((__packed__));

int main(int argc, char * argv[]) {
    
    printf("sizeof(int)=%lu,sizeof(short)=%lu.sizeof(char)=%lu\n",sizeof(int),sizeof(short),sizeof(char));
    
    printf("pp=%lu,mm=%lu \n", sizeof(pp),sizeof(mm));
    printf("oo=%lu,xx=%lu \n", sizeof(oo),sizeof(xx));
    printf("mystruct=%lu \n", sizeof(struct MyStruct));
    printf("mystruct1=%lu \n", sizeof(struct MyStruct1));
    printf("mystruct2=%lu \n", sizeof(struct MyStruct2));
    printf("mystruct3=%lu \n", sizeof(struct MyStruct3));
    printf("mystruct4=%lu \n", sizeof(struct MyStruct4));

    
    printf("sizeof(struct unpacked_struct) = %lu\n", sizeof(struct unpacked_struct));
    printf("sizeof(struct packed_struct_1) = %lu\n", sizeof(struct packed_struct_1));
    printf("sizeof(struct packed_struct_2) = %lu\n", sizeof(struct packed_struct_2));

    
    printf("sizeof(struct Test1) = %lu\n", sizeof(struct Test1));
    printf("sizeof(struct Test2) = %lu\n", sizeof(struct Test2));

    return 0;
}

