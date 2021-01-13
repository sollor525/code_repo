#!/bin/bash  

#计算100以内能被3整除的数的和


sum=0  
for num in $(seq 100)  
do  
    let mod=num%3  
    if [ $mod -eq 0 ]   
    then  
        let sum=sum+num  
    fi  
done  
echo "sum = $sum"  
  
exit 0  