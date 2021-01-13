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

# modify mysql password to 'IKglobal.com2018'
DEF_PWD=$(grep 'temporary password' /var/log/mysqld.log | awk '{print $NF}')
NEW_PWD="IKglobal.com2018"
#mysql -uroot -p"$DEF_PWD" -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$NEW_PWD';"
mysqladmin -uroot -p"$DEF_PWD" password "$NEW_PWD" 
rc=$?
if [[ $rc -ne 0 ]]; then
    read  -s  -p "Enter your mysql root password:" NEW_PWD 
else
    info_msg "Now mysql default password:'$NEW_PWD', Please change the password as soon as possible."
fi

# config, mysql support event
add_line "event_scheduler=ON" /etc/my.cnf
service_stop "mysqld"
service_start "mysqld"

TODAY_PARTITIONNAME='p'$(date "+%Y%m%d")
TOMORROW_DATETIME=$(date -d +"1 day" "+%Y-%m-%d 00:00:00")
TODAY_ONEHOUR=$(date -d +"1 hour" "+%Y-%m-%d %H:00:00")
CURTM=$(date +%s)
echo "CURTM:$CURTM"
let "CURTM=(CURTM / 300 + 1) * 300"
echo "CURTM2:$CURTM"
TODAY_FIVEMIN=$(date "+%Y-%m-%d %H:%M:00" -d@"$CURTM")

cp ik/ikdb_after.sql.tpl ik/ikdb_after.sql
replace_line "##TODAY_PARTITIONNAME##" "$TODAY_PARTITIONNAME" ik/ikdb_after.sql
replace_line "##TOMORROW_DATETIME##" "$TOMORROW_DATETIME" ik/ikdb_after.sql
replace_line "##TODAY_ONEHOUR##" "$TODAY_ONEHOUR" ik/ikdb_after.sql
replace_line "##TODAY_FIVEMIN##" "$TODAY_FIVEMIN" ik/ikdb_after.sql

# import ik database
mysql -uroot -p"$NEW_PWD" -e 'CREATE DATABASE IF NOT EXISTS `ik` DEFAULT CHARACTER SET utf8'
mysql -uroot -p"$NEW_PWD" ik < ik/ikdb.sql
mysql -uroot -p"$NEW_PWD" ik < ik/ikdb_after.sql
