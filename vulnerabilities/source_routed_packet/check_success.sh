#!/bin/sh
sysctl -a |grep net.ipv4.conf.all.accept_source_route | grep 0