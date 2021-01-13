#!/bin/bash  
  
#判断192.168.1.0/24网络里，当前在线的IP有哪些，能ping通则认为在线


for num in $(seq 25)  
do  
    let num--  
    $(ping 192.168.177.$num 2>&1 /dev/null)  
    if [ $? -eq 0 ]  
    then  
        echo "192.168.1.$num up"  
    else  
        echo "192.168.1.$num down"  
    fi  
done  
  
exit 0  
