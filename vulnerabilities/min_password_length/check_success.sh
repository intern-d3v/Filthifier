#!/bin/sh
grep pam_unix.so /etc/pam.d/common-password | grep minlen= |grep -Po "([7-9]|10)" 