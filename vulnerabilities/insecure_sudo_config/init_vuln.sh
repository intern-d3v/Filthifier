#!/bin/sh
apt -y install sudo; sed -i '/%sudo/c\%sudo ALL=(ALL) NOPASSWD: ALL' /etc/sudoers'