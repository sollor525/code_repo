#!/bin/bash

INT_1=ens37
INT_1_PCI_NUM=02:05.0

HUGEPAGE_SIZE=1024

#解压dpdk和pktgen
tar xvf dpdk-18.05.1.tar.xz 
tar xvf pktgen-3.5.3.tar.xz

#build dpdk
cd dpdk-stable-18.05.1/
make config T=x86_64-native-linuxapp-gcc
make

#insmod igb_uio.ko
modprobe uio
rmmod igb_uio
IGB_UIO_PATH=$(find ./ -name "igb_uio.ko" | head -1)
insmod ${IGB_UIO_PATH}

#down interface
ifconfig ${INT_1} down

#config hugepage
mkdir /mnt/huge 
mount -t hugetlbfs nodev /mnt/huge
echo ${HUGEPAGE_SIZE} > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

#echo hugepage info
cat /proc/meminfo| grep Huge  

#bind interface to igb_uio
./usertools/dpdk-devbind.py -b igb_uio 02:05.0

#leave dpdk and set env
cd ..
export RTE_SDK=$(pwd)/dpdk-stable-18.05.1
export RTE_TARGET=build

#install dep 
yum install lua-devel -y
yum install readline-devel -y
yum install libpcap-devel -y
wget https://repo.ius.io/ius-release-el7.rpm
rpm -Uvh ius-release*rpm  
yum --enablerepo=ius-archive install lua53u* -y
sed -i 's/lua5.3/lua-5.3/g' `grep -rl 'lua5.3' ./`

#install pkt-gen
cd pktgen-3.5.3
make


#./app/x86_64-native-linuxapp-gcc/pktgen -l 2,4,6,8,10,12,14,16,18 --file-prefix ddos02 --socket-mem 2048,2048 -w 0000:5e:00.0 -w 0000:5e:00.1 -w 0000:5f:00.0 -w 0000:5f:00.1 -- -P -T -m "[4:6].0,[8:10].1,[12:14].2,[16:18].3"