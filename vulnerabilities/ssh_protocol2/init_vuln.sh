#!/bin/sh
 if [ "$(grep Protocol /etc/ssh/sshd_config)" ]; then sed -i '/Protocol/cProtocol 1' /etc/ssh/sshd_config ; else echo "Protocol 1" >> /etc/ssh/sshd_config; fi