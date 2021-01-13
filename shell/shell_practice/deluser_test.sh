#!/bin/bash

#批量删除20个用户，用户名为user1-20

for num in $(seq 20)
do
    $(userdel user$num)
done
exit
