#!/bin/bash

#1分10秒的计时器

MIN=1
for ((s=10;s>=0;s--))
do
    echo -n "              "
    echo -ne "\r"
    echo -n "1:${s}"
    echo -ne "\r"
    sleep 1

    if
    [ "$s" -eq "0" ]
    then

        for ((s=59;s>0;s--))
        do
            echo -n "              "
            echo -ne "\r"
            echo -n "0:${s}"
            echo -ne "\r"
            sleep 1
        done
    fi

done
