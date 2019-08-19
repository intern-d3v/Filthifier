#!/bin/sh
sed -i '/Server/d' /etc/apache2/apache2.conf; printf "ServerSingature On
ServerTokens OS" >> /etc/apache2/apache2.conf