FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends mariadb-server && \
    rm -rf /var/lib/apt/lists/*

# Permite conexiones remotas (por defecto solo escucha en 127.0.0.1)
RUN { echo '[mysqld]'; echo 'bind-address = 0.0.0.0'; } \
    > /etc/mysql/mariadb.conf.d/99-custom.cnf

COPY init.sql /docker-entrypoint-initdb.d/init.sql
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3306

CMD ["/entrypoint.sh"]
