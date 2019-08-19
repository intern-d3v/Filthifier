#!/bin/sh
! dpkg -l | grep rsh-server| cut -d" " -f1 |grep ii