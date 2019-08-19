#!/bin/sh
! awk -F: '{print $3}' /etc/passwd | sort |uniq -d