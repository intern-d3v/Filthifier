#!/bin/sh
sed -i '/bind-address/d' /etc/mysql/my.cnf; echo bind-address=0.0.0.0 >> /etc/mysql/my.cnf