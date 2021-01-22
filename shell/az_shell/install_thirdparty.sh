#!/bin/bash

#check sharedfuncs and source it
if [[ -f `pwd`/sharedfuncs ]]; then
	echo "source file: sharedfuncs"
	source sharedfuncs
else
	echo "missing file: sharedfuncs"
	exit 1
fi

#echo msg
info_msg "begin to install all thirdparty"

# check environment
check_os
check_root
check_connection

#replace default yum repo
FLODER=yum_repo
YUM_REPO_PATH=/etc/yum.repos.d/
YUM_BASE=CentOS-Base.repo
YUM_DEBUGINFO=CentOS-Debuginfo.repo
YUM_EPEL=epel.repo

check_folder ${FLODER}
cd ${FLODER}
mv ${YUM_REPO_PATH}${YUM_BASE} ${YUM_REPO_PATH}${YUM_BASE}".bak"
mv ${YUM_REPO_PATH}${YUM_DEBUGINFO} ${YUM_REPO_PATH}${YUM_DEBUGINFO}".bak"
mv ${YUM_REPO_PATH}${YUM_EPEL} ${YUM_REPO_PATH}${YUM_EPEL}".bak"
cp ${YUM_BASE}  ${YUM_REPO_PATH}
cp ${YUM_DEBUGINFO}  ${YUM_REPO_PATH}
cp ${YUM_EPEL}  ${YUM_REPO_PATH}

yum clean all
yum makecache
cd ..

# install 
package_install "lrzsz"
package_install "net-tools"
package_install "pciutils"
package_install "libpcap-devel.x86_64"
package_install "python-setuptools"
package_install "nasm"
package_install "tcl"
package_install "expect"
package_install "lshw"
package_install "kernel-devel-3.10.0-1127"



# inatall pip
package_install "python-pip"

#install wheel
cd thirdparty
tar xvf wheel-0.36.2.tar.gz
cd wheel-0.36.2
python setup.py install 
cd ..
rm -rf wheel-0.36.2

#install prompt_toolkit(must install  wcwidth first)
pip install wcwidth-0.1.7-py2.py3-none-any.whl 
pip install prompt_toolkit-1.0.15-py2-none-any.whl

#install treelib 
tar xvf treelib-1.5.1.tar.gz
cd treelib-1.5.1
python setup.py install 
cd ..
rm -rf treelib-1.5.1

#install configparser
pip install configparser-4.0.2-py2.py3-none-any.whl

info_msg "install is done."
