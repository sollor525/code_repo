/*************************************************************************************
__attribute((aligned (n)))，让所作用的结构成员对齐在n字节自然边界上。
如果结构中有成员的长度大于n，则按照最大成员的长度来对齐。
如果aligned后面不指定数值，那么编译器将依据你的目标机器情况使用最大最有益的对齐方式。
**************************************************************************************/

#include <stdio.h>

struct S1 {
    short b[3];
};

struct S2 {
    short b[3];
} __attribute__((aligned(8)));

struct S3 {
    short b[3];
} __attribute__((aligned(16)));

struct S4 {
    short b[3];
} __attribute__((aligned(32)));

struct S5 {
    short b[3];
} __attribute__((aligned(64)));

struct S6 {
    short b[3];
} __attribute__((aligned));


struct A {
    int a;
    char b;
    short c;
} aa;

struct AP {
    int a;
    char b;
    short c;
} __attribute__((aligned(16))) ap;

struct B {
    char a;
    int b;
    short c;
} bb;

struct BP {
    char a;
    int b;
    short c;
} __attribute__((aligned(4))) bp;

struct C {
    int a;
    char b;
    struct AP px;
    short c;
} cc;

struct CP1 {
    int a;
    char b;
    struct AP px;
    short c;
} __attribute__((aligned(4))) cp1;

struct CP2 {
    int a;
    char b;
    struct AP px;
    short c;
} __attribute__((aligned(8))) cp2;


int main(int argc, char** argv)
{
    printf("sizeof(struct S1) = %ld\n", sizeof(struct S1));
    printf("sizeof(struct S2) = %ld\n", sizeof(struct S2));
    printf("sizeof(struct S3) = %ld\n", sizeof(struct S3));
    printf("sizeof(struct S4) = %ld\n", sizeof(struct S4));
    printf("sizeof(struct S5) = %ld\n", sizeof(struct S5));
    printf("sizeof(struct S6) = %ld\n", sizeof(struct S6));

    printf("sizeof(aa) = %lu, sizeof(ap) = %lu\n", sizeof(aa), sizeof(ap));
    printf("sizeof(bb) = %lu, sizeof(bp) = %lu\n", sizeof(bb), sizeof(bp));
    printf("sizeof(cc) = %lu, sizeof(cp1) = %lu\n", sizeof(cc), sizeof(cp1));
    printf("sizeof(cc) = %lu, sizeof(cp2) = %lu\n", sizeof(cc), sizeof(cp2));
    
    return 0;
}