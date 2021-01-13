#!/bin/bash  


while : ; do  
        time=`date +%m"-"%d" "%k":"%M`  
    echo time=$time  
        day=`date +%m"-"%d`  
    echo day=$day  
        rx_before=`ifconfig eth0|sed -n "9"p|awk '{print $1}'|cut -d: -f2`  
    echo rx_before=$rx_before  
        tx_before=`ifconfig eth0|sed -n "9"p|awk '{print $4}'|cut -d: -f2-`  
    echo tx_before=$tx_before  
        sleep 2  
        rx_after=`ifconfig eth0|sed -n "9"p|awk '{print $1}'|cut -d: -f2`  
    echo rx_after=$rx_after  
        tx_after=`ifconfig eth0|sed -n "9"p|awk '{print $4}'|cut -d: -f2`  
    echo tx_after=$tx_after  
        rx_result=$[(rx_after-rx_before)*4]  
    echo rx_result=$rx_result  
        tx_result=$[(tx_after-tx_before)*4]  
    echo tx_result=$tx_result  
        echo "$time Now_In_Speed: "$rx_result"bps Now_Out_Speed: "$tx_result"bps"  
        sleep 2  
done  

