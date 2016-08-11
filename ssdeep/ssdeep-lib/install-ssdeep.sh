#!/bin/sh
SSDEEP_VERSION="2.13"

TMP_PATH=/var/tmp/
REP_PATH=`pwd`

MAKE=make
WGET=wget
SUDO=sudo

cd ${TMP_PATH}
${WGET} -O ssdeep.tar.gz https://sourceforge.net/projects/ssdeep/files/ssdeep-2.13/ssdeep-2.13.tar.gz/download
tar zxvf ssdeep.tar.gz
cd ssdeep-${SSDEEP_VERSION}/
cp "${REP_PATH}/ssdeep/ssdeep-lib/ac-fix/*" ./
./configure
${MAKE}
${SUDO} ${MAKE} install
cd ../
rm -rf ssdeep-${SSDEEP_VERSION}
rm ssdeep.tar.gz 

