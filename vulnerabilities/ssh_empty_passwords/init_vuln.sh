#!/bin/sh
sed -i '/PermitEmptyPasswords/cPermitEmptyPasswords  yes' /etc/ssh/sshd_config