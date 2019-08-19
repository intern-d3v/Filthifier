#!/bin/sh
grep StrictModes /etc/ssh/sshd_config | grep -i yes | grep -v \#