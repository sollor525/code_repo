#!/bin/bash  

#指定目录下普通文件的个数


path=/home/tomwang
count=0  
  
for file in $(ls $path)  
do  
    if [ -f $file ]  
    then  
       let count++  
    fi  
done  
  
echo "count = $count"  
  
exit 0  
