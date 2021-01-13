#!/bin/bash

REDIS_DL="http://download.redis.io/redis-stable.tar.gz"

if [[ -f `pwd`/sharedfuncs ]]; then
  source sharedfuncs
else
  echo "missing file: sharedfuncs"
  exit 1
fi

# check environment
check_os
check_root

if ! is_package_installed "gcc"; then
    package_install "gcc"
fi

! type "redis-server" || (echo "redis has installed"; exit 0)

cd redis
#tar zxf redis-4.0.6.tar.gz
#cd redis-4.0.6; make && make install
#cd deps/hiredis; make && make install
#cd ../../..
#cp utils/redis_init_script ../
#rm -rf redis-4.0.6
wget http://download.redis.io/redis-stable.tar.gz
tar zxf redis-stable.tar.gz
cd redis-stable; make && make install
cd deps/hiredis; make && make install
cd ../../
cp utils/redis_init_script ../
cp redis.conf ../
cd ../
rm -rf redis-stable
   
cp hiredis-x86_64.conf /etc/ld.so.conf.d/
ldconfig

# modify the conf file
replace_line 'tcp-backlog.*$' 'tcp-backlog 128' 'redis.conf'
replace_line '#.*unixsocket' 'unixsocket' 'redis.conf'
replace_line '#.*unixsocketperm' 'unixsocketperm 700' 'redis.conf'
replace_line 'daemonize no' 'daemonize yes' 'redis.conf'
replace_line '#.*save ""' 'save ""' 'redis.conf'
replace_line 'save 900 1' '# save 900 1' 'redis.conf'
replace_line 'save 300 10' '# save 300 10' 'redis.conf'
replace_line 'save 60 10000' '# save 60 10000' 'redis.conf'
replace_line '#.*maxmemory <bytes>' 'maxmemory 536870912' 'redis.conf'
   
mkdir -p /etc/redis
cp redis.conf /etc/redis/6379.conf
cp redis_init_script /etc/init.d/redis_6379
cp redis-server.service /etc/systemd/system/
systemctl enable redis-server.service
systemctl daemon-reload 
systemctl start redis-server.service 
cd ..

