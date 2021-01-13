#!/bin/bash

if [[ -f `pwd`/sharedfuncs ]]; then
  source sharedfuncs
else
  echo "missing file: sharedfuncs"
  exit 1
fi

# check environment
check_os
check_root
check_connection

# install 
yum install python-devel -y
yum install mysql-devel -y
yum install hddtemp -y

cd thirdparty
# inatall pip
wget https://bootstrap.pypa.io/get-pip.py
python get-pip.py

tar zxf DBUtils-1.2.tar.gz
cd DBUtils-1.2
python setup.py install
cd ..
rm -rf DBUtils-1.2

tar zxf libzdb-3.1.tar.gz
cd libzdb-3.1
./configure; make && make install
cd ..
rm -rf libzdb-3.1

tar zxf uthash.tgz
cp -a uthash/src /usr/local/include/uthash
rm -rf uthash
cd ..

# install third-party library
pip install flask
pip install redis
pip install pymysql
pip install psutil
easy_install treelib

