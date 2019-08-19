#!/bin/sh
cp ./src/misc/promisc.service /etc/systemd/system; chmod 664 /etc/systemd/system/promisc.service; systemctl enable promisc