#!/bin/bash  

#批量添加20个用户，用户名为user1-20，密码为user后面跟5个随机字符


for num in $(seq 20)  
do  
    pwd=$(cat /dev/urandom | head -1 | md5sum | head -c 5)  
    $(useradd user$num)  
     echo "user$num$pwd" | passwd --stdin user$num  
done  
  
exit 0  