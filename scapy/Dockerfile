# Misma base que servidor y cliente para mantener el entorno homogéneo.
FROM ubuntu:22.04

# Evita que apt lance diálogos interactivos durante el build.
ENV DEBIAN_FRONTEND=noninteractive

# tshark (wireshark-common) pregunta si permite captura a usuarios no-root.
# Preconfiguramos la respuesta para que el build no se quede esperando input.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" \
        | debconf-set-selections

# Dependencias del sistema:
#   python3 / python3-pip / python3-dev  → runtime de Scapy y compilar bindings.
#   build-essential                      → gcc, necesario para compilar NetfilterQueue.
#   libnetfilter-queue-dev / libnfnetlink-dev → cabeceras de NFQUEUE.
#   iptables                             → redirigir tráfico a la cola NFQUEUE.
#   tcpdump / tshark                     → verificar/depurar la captura.
#   iproute2 / net-tools / iputils-ping  → ip, ifconfig, ping para diagnóstico.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-dev \
        build-essential \
        libnetfilter-queue-dev \
        libnfnetlink-dev \
        iptables \
        tcpdump \
        tshark \
        iproute2 \
        net-tools \
        iputils-ping && \
    rm -rf /var/lib/apt/lists/*

# Scapy y NetfilterQueue vía pip: trae versiones más nuevas que las de apt.
# NetfilterQueue es el binding moderno de python3 para NFQUEUE (se compila
# contra libnetfilter-queue-dev, por eso instalamos build-essential arriba).
RUN pip3 install --no-cache-dir --upgrade scapy NetfilterQueue

# Directorio donde montaremos y editaremos los scripts de Scapy desde el host.
WORKDIR /scripts

# Mantiene el contenedor vivo sin proceso principal propio, para entrar con
# "docker exec" y lanzar los scripts manualmente.
CMD ["tail", "-f", "/dev/null"]
