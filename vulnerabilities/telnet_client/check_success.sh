#!/bin/sh
! dpkg -l | grep telnet | cut -d" " -f1 |grep ii