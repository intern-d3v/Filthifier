#!/bin/sh
grep PASS_MIN_DAYS /etc/login.defs | grep -Po "([7-9]|10)"