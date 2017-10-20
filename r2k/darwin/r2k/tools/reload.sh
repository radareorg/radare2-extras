#!/bin/sh

LE=/Library/Extensions
NM=r2k.kext
KM=${LE}/${NM}
BD=~/Library/Developer/Xcode/DerivedData/*/Build/Products/Debug/r2k.kext

kextunload ${KM} &>/dev/null
rm -rf ${KM}
cp -a ${BD}${NM} ${LE}
chown -R root ${KM}
chgrp -R wheel ${KM}
kextload ${KM}
