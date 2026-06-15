#!/bin/bash
set -e

if [ ! -d "/var/lib/mysql/mysql" ]; then
    mysql_install_db --user=mysql --datadir=/var/lib/mysql
fi

# --skip-networking: solo socket local durante la inicialización
mysqld_safe --skip-networking &

until mysqladmin ping --silent 2>/dev/null; do
    sleep 1
done

mysql -u root < /docker-entrypoint-initdb.d/init.sql

mysqladmin -u root shutdown
sleep 2

# exec reemplaza bash por mariadbd como PID 1
exec mariadbd --user=mysql
