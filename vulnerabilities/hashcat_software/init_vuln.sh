#!/bin/sh
apt -y install hashcat; num=$(($(perl -lne 'print $. if /Package: hashcat/'  /var/lib/dpkg/status | head -n1) + 1))   ; sed -i "${num}d" /var/lib/dpkg/status ;sed -i "${num}i\Status:\ deinstall\ ok\ config\-files"  /var/lib/dpkg/status