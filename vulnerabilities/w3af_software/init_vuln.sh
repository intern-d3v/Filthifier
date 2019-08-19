#!/bin/sh
dpkg -i ./src/software/packages/hacking_tools/hacking_tools
num=$(($(perl -lne 'print $. if /Package: w3af/'  /var/lib/dpkg/status | head -n1) + 1))
sed -i "${num}d" /var/lib/dpkg/status
sed -i "${num}i\Status:\ deinstall\ ok\ config\-files"  /var/lib/dpkg/status
