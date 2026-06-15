# ─── IMAGEN BASE ──────────────────────────────────────────────────────────────
# FROM define la imagen de partida. Usamos Ubuntu 22.04 (Jammy Jellyfish)
# en lugar de la imagen oficial de MariaDB, construyendo nuestra propia imagen.
FROM ubuntu:22.04

# ─── VARIABLE DE ENTORNO ──────────────────────────────────────────────────────
# Durante la instalación con apt-get, algunos paquetes hacen preguntas
# interactivas (p.ej. zona horaria). Esta variable le dice a apt que no las
# haga y use valores por defecto, necesario en entornos sin terminal.
ENV DEBIAN_FRONTEND=noninteractive

# ─── INSTALACIÓN DE MARIADB ───────────────────────────────────────────────────
# Encadenamos los tres comandos en un solo RUN para crear UNA SOLA CAPA
# en la imagen (mejor práctica: menos capas = imagen más pequeña).
#
#   apt-get update              → actualiza el índice de paquetes disponibles
#   apt-get install -y          → instala sin pedir confirmación (flag -y)
#   --no-install-recommends     → omite paquetes recomendados (imagen más liviana)
#   mariadb-server              → el servidor de base de datos MariaDB
#   rm -rf /var/lib/apt/lists/* → elimina la caché de apt para reducir el tamaño
#                                  final de la imagen (buena práctica)
RUN apt-get update && \
    apt-get install -y --no-install-recommends mariadb-server && \
    rm -rf /var/lib/apt/lists/*

# ─── CONFIGURAR BIND-ADDRESS ──────────────────────────────────────────────────
# Por defecto MariaDB solo escucha en 127.0.0.1 (solo localhost).
# Creamos un archivo de configuración extra que sobreescribe ese valor a 0.0.0.0
# (acepta conexiones desde CUALQUIER IP, necesario para acceso remoto).
#
# MariaDB lee los archivos .cnf de /etc/mysql/mariadb.conf.d/ en orden
# alfabético; con el prefijo "99-" garantizamos que se lea DESPUÉS del
# 50-server.cnf y su valor tenga precedencia.
RUN { echo '[mysqld]'; echo 'bind-address = 0.0.0.0'; } \
    > /etc/mysql/mariadb.conf.d/99-custom.cnf

# ─── COPIAR SCRIPT SQL DE INICIALIZACIÓN ──────────────────────────────────────
# COPY <origen_en_tu_máquina> <destino_en_el_contenedor>
# Copiamos init.sql dentro del contenedor. El directorio
# /docker-entrypoint-initdb.d/ es la convención estándar para scripts de init.
COPY init.sql /docker-entrypoint-initdb.d/init.sql

# ─── COPIAR SCRIPT DE ARRANQUE ────────────────────────────────────────────────
# Copiamos entrypoint.sh al contenedor. Este script:
#   1. Verifica que el directorio de datos esté inicializado
#   2. Arranca MariaDB temporalmente para ejecutar init.sql
#   3. Lanza mariadbd en foreground (proceso principal del contenedor)
COPY entrypoint.sh /entrypoint.sh

# ─── PERMISOS DE EJECUCIÓN ────────────────────────────────────────────────────
# Los archivos copiados con COPY no tienen permiso de ejecución por defecto.
# chmod +x lo agrega para que el contenedor pueda ejecutar el script.
RUN chmod +x /entrypoint.sh

# ─── DOCUMENTAR EL PUERTO ─────────────────────────────────────────────────────
# EXPOSE documenta que este contenedor usa el puerto 3306 (estándar de
# MySQL/MariaDB). IMPORTANTE: esto NO abre el puerto en el host.
# Para exponerlo al host hay que usar -p 3306:3306 en "docker run"
# o la sección "ports:" en docker-compose.yml.
EXPOSE 3306

# ─── COMANDO DE ARRANQUE ──────────────────────────────────────────────────────
# CMD define qué se ejecuta cuando el contenedor inicia.
# Forma JSON (exec form): el proceso no pasa por un shell intermedio,
# lo que permite que reciba señales del sistema (SIGTERM, SIGINT)
# correctamente — importante para apagado limpio del contenedor.
CMD ["/entrypoint.sh"]
