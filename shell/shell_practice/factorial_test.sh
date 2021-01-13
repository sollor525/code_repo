#!/bin/bash  

#求10的阶乘


sum=1  
for num in $(seq 10)  
do  
    let sum=sum*num  
done  
  
echo "sum = $sum"  
  
exit 0  