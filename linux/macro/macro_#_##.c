/* 
 * C宏定义中#和##：
 * #的作用是把参数字符串化. 相当于给参数加上引号。
 * ##的作用是把前后字符连接起来, 不会在前后加引号。
 * 
 * gcc -E macro_#_##.c -o macro_#_##.i 
 * 然后 cat macro.i 即可看到预编译结果。
 *
 * “#”即先展开左右的宏，再以字符串形式拼接起来。
 * “##”即先拼接左右的字符串，再根据拼接起来的结果是不是宏再另行展开。
*/


#include<stdio.h>

#define FILE_NAME "/dev/tty"
#define FILE_NAME2 "/dev/console"

// '#' use example
#define FILE_OPEN1(fd,n) \
{ \
	fd = open(FILE_NAME#n,O_RDWR); \
	if(fd < 0){ \
	printf("open tty error\n"); \
		return 0; \
	} \
}
 
// '##' use example
#define FILE_OPEN2(fd,n) \
{ \
	fd = open(FILE_NAME##n,O_RDWR); \
	if(fd < 0){ \
	printf("open tty error\n"); \
		return 0; \
	} \
}
 
 
int main(void)
{
	FILE_OPEN1(fd1, 1);     //相当于open("/dev/tty""1",O_RDWR)
	FILE_OPEN1(fd2, 2);	//相当于open("/dev/tty""2",O_RDWR)
	FILE_OPEN1(fd3, 3);	//相当于open("/dev/tty""3",O_RDWR)
 
	FILE_OPEN2(fd4, 1);	//相当于open(FILE_NAME1,O_RDWR)
	FILE_OPEN2(fd5, 2);	//相当于open("/dev/console",O_RDWR)
	FILE_OPEN2(fd6, 3);	//相当于open(FILE_NAME3,O_RDWR)
	return 0;
}
