#!/bin/sh
sed -i '/PermitRootLogin/cPermitRootLogin yes' /etc/ssh/sshd_config