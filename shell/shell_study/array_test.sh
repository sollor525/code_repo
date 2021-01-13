#!/usr/bin/env bash


#Shell 数组
# bash支持一维数组（不支持多维数组），并且没有限定数组的大小。
# 类似与C语言，数组元素的下标由0开始编号。获取数组中的元素要利用下标，下标可以是整数或算术表达式，其值应大于或等于0。
# 在Shell中，用括号来表示数组，数组元素用"空格"符号分割开。
array_name1=(A B "C" D)
array_name2=(
value0
value1
value2
value3
)
array_name3[0]=value0
array_name3[1]=value1
array_name3[2]=valuen


#读取数组
my_array=(A B "C" D)
echo "第一个元素为: ${my_array[0]}"
echo "第二个元素为: ${my_array[1]}"
echo "第三个元素为: ${my_array[2]}"
echo "第四个元素为: ${my_array[3]}"


#获取数组中的所有元素
my_array[0]=A
my_array[1]=B
my_array[2]=C
my_array[3]=D
echo "数组的元素为: ${my_array[*]}"
echo "数组的元素为: ${my_array[@]}"


#获取数组的长度: 获取数组长度的方法与获取字符串长度的方法相同
my_array[0]=ABC
my_array[1]=BCD
my_array[2]=CDE
my_array[3]=DEFF
echo "数组元素个数为: ${#my_array[*]}"
echo "数组元素个数为: ${#my_array[@]}"


# 取得数组单个元素的长度
lengthn=${#my_array[3]}
echo $lengthn
