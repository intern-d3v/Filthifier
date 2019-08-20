echo -e "<VirtualHost *:800>
DocumentRoot /
</VirtualHost>" >> /etc/apache2/sites-enabled/000-default.conf; echo Listen 800 >> /etc/apache2/ports.conf