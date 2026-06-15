FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wget \
        unzip \
        curl && \
    rm -rf /var/lib/apt/lists/*

# CloudBeaver requiere Java 21; Ubuntu 22.04 solo tiene Java 17 en sus repos.
# Se copia el runtime directamente desde la imagen oficial (build multi-stage).
COPY --from=dbeaver/cloudbeaver:latest /opt/java/openjdk /opt/java/openjdk

ENV JAVA_HOME=/opt/java/openjdk
ENV PATH=$JAVA_HOME/bin:$PATH

# CloudBeaver CE no distribuye binarios independientes; se obtiene desde su imagen Docker.
COPY --from=dbeaver/cloudbeaver:latest /opt/cloudbeaver /opt/cloudbeaver

WORKDIR /opt/cloudbeaver

EXPOSE 8978

CMD ["./run-cloudbeaver-server.sh"]
