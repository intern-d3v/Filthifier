#!/bin/sh
sed -i '/-FollowSymLinks/d' /etc/apache2/apache2.conf; sed -r -i -e 's|^([[:space:]]*)</Directory>|\1\tOptions Indexes\n\1</Directory>|g' /etc/apache2/apache2.conf