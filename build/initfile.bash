#!/bin/bash
useradd anastassia -s '/bin/bash' -p $(mkpasswd --method=sha512 JDprLk) -m 
useradd twila -s '/bin/bash' -p $(mkpasswd --method=sha512 HQTFZn) -m 
useradd estell -s '/bin/bash' -p $(mkpasswd --method=sha512 xoz3FkTrUj) -m 
useradd mauricio -s '/bin/bash' -p $(mkpasswd --method=sha512 WxVonv) -m 
useradd erinn -s '/bin/bash' -p $(mkpasswd --method=sha512 AittvVWQ) -m 
useradd natassja -s '/bin/bash' -p $(mkpasswd --method=sha512 M970EDK9vXg) -m 
useradd bettye -s '/bin/bash' -p $(mkpasswd --method=sha512 Y3TUdbCEHhWB) -m 
useradd rochell -s '/bin/bash' -p $(mkpasswd --method=sha512 jJ5DO3bUD8) -m 
dpkg -i ./src/software/packages/services/openssh-server/*

sed -i '/PermitRootLogin/cPermitRootLogin yes' /etc/ssh/sshd_config
