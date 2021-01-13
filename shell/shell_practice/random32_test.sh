#!/bin/bash  
  
#随机生成32位密码


psd="/proc/sys/kernel/random/uuid"  
echo $(cat $psd)  
  
exit 0  