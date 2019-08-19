#!/bin/sh
 ls -la /var/log/syslog | cut -d' ' -f3 | grep syslog && stat -c '%a' /var/log/syslog | grep 640