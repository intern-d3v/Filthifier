#!/bin/sh
sed -i '/UsePrivilegeSeparation/cUsePrivilegeSeparation no' /etc/ssh/sshd_config