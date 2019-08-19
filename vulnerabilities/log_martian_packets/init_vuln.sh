#!/bin/bash
#!/bin/bash
lineNumWithi="$(( $RANDOM % 20 + 10 ))i"
sed -i "/net.ipv4.conf.default.log_martian/d" /etc/sysctl.conf
sed -i "$lineNumWithi net.ipv4.conf.default.log_martian\ =\ 0" /etc/sysctl.conf

