#!/usr/bin/env bash

#用户输入一个ip，检测这个ip的那台主机是否开机

read -p "please input ip:" IP
ping $IP -w 1s &> /dev/null && echo $IP is up || echo $IP is down
