#!/bin/bash  
  
#把给定目录下的所有普通文件更改名字为1，2，3.....


path=/home/wzh  
index=1  
  
for file in $(ls $path)  
do  
    if [ -f $file ]  
    then  
       $(mv $file $index)  
       let index++  
    fi  
done  
  
exit 0  