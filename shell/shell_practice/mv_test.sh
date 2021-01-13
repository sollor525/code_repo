#!/bin/bash  
  
#将/usr/local/test 目录下大于100K 的文件转移到/tmp 目录下


path="/usr/local/test"  
for file in $(ls $path)  
do  
    if [ -f $file ]  
    then  
       if [ $(ls -l $file | cut -f5 -d" ") -gt 100000 ]    
       then  
           $(mv $file /tmp)  
       fi  
    fi  
done  
  
exit 0  

