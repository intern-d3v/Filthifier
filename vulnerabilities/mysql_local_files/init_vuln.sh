#!/bin/sh
sed -i '/local-infile/d' /etc/mysql/my.cnf; echo local-infile=1 >> /etc/mysql/my.cnf