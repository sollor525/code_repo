#!/bin/bash  

#删除给定目录下大小为0的文件


path=/home/wzh  
  
for file in $(ls $path)  
do  
    num=$(ls -l $file | cut -f5 -d" ")  
    if [ $num -eq 0 ]  
    then  
       $(rm $path/$file)  
    fi  
done  
  
exit 0  