#!/bin/sh
sysctl -a | grep net.ipv4.conf.default.log_martians | grep 1