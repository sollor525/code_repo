#!/usr/bin/env bash

#Shell 输入/输出重定向
#   command > file	将输出重定向到 file。
#   command < file	将输入重定向到 file。
#   command >> file	将输出以追加的方式重定向到 file。
#   n > file	将文件描述符为 n 的文件重定向到 file。
#   n >> file	将文件描述符为 n 的文件以追加的方式重定向到 file。
#   n >& m	将输出文件 m 和 n 合并。
#   n <& m	将输入文件 m 和 n 合并。
#   << tag	将开始标记 tag 和结束标记 tag 之间的内容作为输入。
#需要注意的是文件描述符 0 通常是标准输入（STDIN），1 是标准输出（STDOUT），2 是标准错误输出（STDERR）。


#输出重定向
echo "菜鸟教程：www.runoob.com" > users
echo "菜鸟教程：www.runoob.com" >> users


#输入重定向
wc -l users
wc -l < users
#第一个例子，会输出文件名；第二个不会，因为它仅仅知道从标准输入读取内容。


#   标准输入文件(stdin)：stdin的文件描述符为0，Unix程序默认从stdin读取数据。
#   标准输出文件(stdout)：stdout 的文件描述符为1，Unix程序默认向stdout输出数据。
#   标准错误文件(stderr)：stderr的文件描述符为2，Unix程序会向stderr流中写入错误信息。

#将 stdout 重定向到 file:            command > file 
#将 stdin 重定向到 file:             command < file 
#将 stderr 重定向到 file:            command 2 > file
#将 stderr 追加到 file 文件末尾:     command 2 >> file
#将 stdout 和 stderr 合并后重定向到 file:     command > file 2>&1   或者    command >> file 2>&1
#将 stdin 重定向到 file1，将 stdout 重定向到 file2:    command < file1 >file2


#Here Document
#Here Document 是 Shell 中的一种特殊的重定向方式，用来将输入重定向到一个交互式 Shell 脚本或程序。
wc -l << EOF
    欢迎来到
    菜鸟教程
    www.runoob.com
EOF

cat << EOF
欢迎来到
菜鸟教程
www.runoob.com
EOF


#/dev/null 文件
#如果希望执行某个命令，但又不希望在屏幕上显示输出结果，那么可以将输出重定向到 /dev/null
#command > /dev/null
#如果希望屏蔽 stdout 和 stderr
#command > /dev/null 2>&1






