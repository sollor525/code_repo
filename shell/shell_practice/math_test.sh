#!/bin/bash  

#利用shift计算所有参数的乘积，假设参数都是整数


function GetResult(){  
    sum=1  
    while [ $# -gt 0 ]  
    do  
         let sum=sum*$1  
         shift  
    done  
    echo "sum = $sum"  
}  
  
GetResult 1 2 3 4 5  
exit 0  