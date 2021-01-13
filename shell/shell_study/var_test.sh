#!/bin/bash
echo "Hello World !"

#   1) 局部变量 局部变量在脚本或命令中定义，仅在当前shell实例中有效，其他shell启动的程序不能访问局部变量。
#   2) 环境变量 所有的程序，包括shell启动的程序，都能访问环境变量，有些程序需要环境变量来保证其正常运行。必要的时候shell脚本也可以定义环境变量。
#   3) shell变量 shell变量是由shell程序设置的特殊变量。shell变量中有一部分是环境变量，有一部分是局部变量，这些变量保证了shell的正常运行

#变量赋值
var_1="sting"
echo "var_1 is ${var_1}, just for fun"


#使用变量：使用一个定义过的变量，只要在变量名前面加美元符号即可。变量名外面的花括号是可选的，推荐给所有变量加上花括号。
your_name="qinjx"
echo $your_name
echo ${your_name}


your_name="tom"
echo $your_name
your_name="alibaba"
echo $your_name


#只读变量: 使用 readonly 命令可以将变量定义为只读变量，只读变量的值不能被改变。
#!/bin/bash
myUrl="http://www.w3cschool.cc"
readonly myUrl
myUrl="http://www.runoob.com"


#删除变量
#!/bin/sh
myUrl1="http://www.runoob.com"
unset myUrl1
echo $myUrl1


#单引号: 单引号里的任何字符都会原样输出，单引号字符串中的变量是无效的; 单引号字串中不能出现单引号（对单引号使用转义符后也不行）。
str='this is a string'


#双引号: 双引号里可以有变量, 双引号里可以出现转义字符
your_name='qinjx'
str="Hello, I know your are \"$your_name\"! \n"


#拼接字符串
your_name="qinjx"
greeting="hello, "$your_name" !"
greeting_1="hello, ${your_name} !"
echo $greeting $greeting_1


# 获取字符串长度
string="abcd"
echo ${#string} #输出 4


# 提取子字符串
string="runoob is a great site"
echo ${string:1:4} # 输出 unoo


# 查找子字符串: 查找字符 "i 或 s" 的位置
string="runoob is a great company"
echo `expr index "$string" is`  # 输出 8







