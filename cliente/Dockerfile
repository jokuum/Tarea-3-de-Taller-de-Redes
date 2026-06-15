# ─── IMAGEN BASE ──────────────────────────────────────────────────────────────
# Partimos de Ubuntu 22.04, igual que el servidor.
# La tarea exige construir nuestra propia imagen sin usar la imagen oficial
# de CloudBeaver directamente como base de ejecución.
FROM ubuntu:22.04

# ─── VARIABLE DE ENTORNO ──────────────────────────────────────────────────────
# Evita preguntas interactivas de apt-get durante el build
# (por ejemplo, selección de zona horaria al instalar Java).
ENV DEBIAN_FRONTEND=noninteractive

# ─── INSTALACIÓN DE DEPENDENCIAS ──────────────────────────────────────────────
# CloudBeaver es una aplicación Java, por eso necesitamos herramientas base:
#   wget  → descarga de archivos desde la red
#   unzip → extracción de archivos ZIP
#   curl  → transferencias HTTP (diagnóstico y healthchecks)
# Java se obtiene directamente desde la imagen oficial (ver más abajo),
# garantizando compatibilidad de versión exacta (Java 21 Temurin).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wget \
        unzip \
        curl && \
    rm -rf /var/lib/apt/lists/*

# ─── OBTENER JAVA 21 (build multi-stage) ─────────────────────────────────────
# CloudBeaver 26.x requiere Java 21 (compilado con class version 65).
# Ubuntu 22.04 solo incluye Java 17 en sus repos oficiales, por lo que
# copiamos el runtime Java 21 (Temurin) directamente desde la imagen oficial
# de CloudBeaver, donde reside en /opt/java/openjdk.
# COPY --from extrae archivos de otra imagen SIN hacerla parte del resultado:
# la imagen final sigue siendo ubuntu:22.04, solo tomamos prestados los archivos.
COPY --from=dbeaver/cloudbeaver:latest /opt/java/openjdk /opt/java/openjdk

# ─── CONFIGURAR JAVA EN EL PATH ───────────────────────────────────────────────
# ENV establece variables de entorno permanentes dentro del contenedor.
#   JAVA_HOME → directorio raíz de la instalación de Java
#   PATH      → añade los binarios de Java (java, javac, etc.) al PATH del sistema
# Sin esto, el script de CloudBeaver no encontraría el comando 'java'.
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH=$JAVA_HOME/bin:$PATH

# ─── OBTENER CLOUDBEAVER (build multi-stage) ──────────────────────────────────
# CloudBeaver CE NO distribuye binarios independientes para Linux.
# Su única distribución oficial son los archivos dentro de su imagen Docker
# en Docker Hub (dbeaver/cloudbeaver:latest).
#
# COPY --from=<imagen> permite copiar archivos DESDE otra imagen hacia la
# nuestra, sin que esa imagen forme parte del resultado final.
# Esto se llama "build multi-stage": Docker descarga dbeaver/cloudbeaver
# solo durante el build para extraer los archivos, pero la imagen que
# ejecuta el contenedor sigue siendo 100% ubuntu:22.04.
#
# Los archivos de CloudBeaver viven en /opt/cloudbeaver dentro de su imagen.
COPY --from=dbeaver/cloudbeaver:latest /opt/cloudbeaver /opt/cloudbeaver

# ─── DIRECTORIO DE TRABAJO ────────────────────────────────────────────────────
# Todos los comandos siguientes (y el CMD) se ejecutan desde este directorio.
# run-cloudbeaver-server.sh usa rutas relativas, por eso es importante estar aquí.
WORKDIR /opt/cloudbeaver

# ─── EXPONER EL PUERTO ────────────────────────────────────────────────────────
# CloudBeaver sirve su interfaz web en el puerto 8978 por defecto.
# EXPOSE documenta el puerto; para accederlo desde el host hay que
# mapearlo con -p 8978:8978 en "docker run".
EXPOSE 8978

# ─── COMANDO DE ARRANQUE ──────────────────────────────────────────────────────
# run-cloudbeaver-server.sh es el script oficial de inicio de CloudBeaver.
# Lo ejecutamos en forma JSON (exec form) para que sea el PID 1 del
# contenedor y reciba señales del sistema correctamente.
# Al correr en foreground, el contenedor permanece activo mientras
# CloudBeaver esté funcionando.
CMD ["./run-cloudbeaver-server.sh"]
