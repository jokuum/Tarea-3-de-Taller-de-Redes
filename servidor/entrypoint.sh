#!/bin/bash
# Salir inmediatamente si cualquier comando falla
set -e

# Si el directorio de datos no existe, inicializarlo
# (en algunos entornos el apt-get no completa la inicialización)
if [ ! -d "/var/lib/mysql/mysql" ]; then
    echo ">>> Inicializando directorio de datos de MariaDB..."
    mysql_install_db --user=mysql --datadir=/var/lib/mysql
fi

# Arrancar MariaDB en SEGUNDO PLANO y solo por socket Unix
# --skip-networking evita aceptar conexiones TCP mientras hacemos el setup
echo ">>> Iniciando MariaDB temporalmente (solo socket local)..."
mysqld_safe --skip-networking &

# Esperar hasta que el servidor responda al ping por socket
echo ">>> Esperando que MariaDB esté listo..."
until mysqladmin ping --silent 2>/dev/null; do
    sleep 1
done

# Ejecutar el script SQL de inicialización como root (auth por socket)
echo ">>> Ejecutando init.sql..."
mysql -u root < /docker-entrypoint-initdb.d/init.sql

# Apagar el servidor temporal de forma ordenada
echo ">>> Deteniendo MariaDB temporal..."
mysqladmin -u root shutdown
sleep 2

# Arrancar MariaDB en PRIMER PLANO (foreground)
# 'exec' reemplaza el proceso bash por mariadbd, que pasa a ser PID 1
# Docker monitorea ese PID; si termina, el contenedor se detiene
echo ">>> Iniciando MariaDB en foreground..."
exec mariadbd --user=mysql
