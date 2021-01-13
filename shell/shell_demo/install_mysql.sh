#!/bin/bash

# GLOBAL VARIABLES
MYSQL="mysqld.service"
MYSQL_REPO="mysql.*-community.*"
MYSQL_REPO_URL="http://dev.mysql.com/get/mysql57-community-release-el7-8.noarch.rpm"
MYSQL_PKT="mysql-community-server"

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

if is_package_installed "${MYSQL_PKT}"; then
    info_msg "${MYSQL_PKT} has installed."
    exit 0
fi

package_localinstall ${MYSQL_REPO_URL}

if ! check_repository "${MYSQL_REPO}"; then
    error_msg "Error, there is no mysql repository"
fi

package_install "${MYSQL_PKT}"    

# install service
service_start "${MYSQL}"
service_install "${MYSQL}"

DEFPASSWD=$(grep 'temporary password' /var/log/mysqld.log | awk '{print $NF}')
info_msg "MySQL default password:${DEFPASSWD}"
info_msg "Please configure MySQL by yourself and enjoy it."

