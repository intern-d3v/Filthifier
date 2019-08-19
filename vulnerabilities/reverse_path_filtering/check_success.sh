#!/bin/sh
sysctl -a |grep net.ipv4.conf.all.rp_filter /| grep 1