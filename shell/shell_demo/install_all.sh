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

./install_mysql.sh
./install_redis.sh
./install_thirdparty.sh
./install_ddos_statmod.sh

