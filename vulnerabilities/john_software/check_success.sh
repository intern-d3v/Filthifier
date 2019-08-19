#!/bin/sh
! dpkg -l | grep  john | cut -d" " -f1 |grep ii