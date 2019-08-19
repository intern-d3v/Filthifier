#!/bin/sh
grep pam_cracklib.so /etc/pam.d/common-password | sed 's/ //g' |grep -E 'ucredit\=\-1.*lcredit\=\-1.*dcredit\=\-1.*ocredit\=\-1'