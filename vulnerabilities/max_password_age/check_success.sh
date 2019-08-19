#!/bin/sh
grep PASS_MAX_DAYS /etc/login.defs | grep -Po "([3-8][0-9]|90)"