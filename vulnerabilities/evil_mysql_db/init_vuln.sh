#!/bin/sh
mysql -u root -ppassword -e "CREATE DATABASE TEST; exit;mysql -u root -ppassword TEST < ./src/misc/evilData.sql"