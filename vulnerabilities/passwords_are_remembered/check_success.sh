#!/bin/sh
grep pam_unix.so /etc/pam.d/common-password |grep remember=| grep -Po "([3-5])" 