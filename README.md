# Tarea 2 — Taller de Redes

> Despliegue contenerizado de un servidor MariaDB y un cliente web CloudBeaver utilizando Docker Compose, con análisis del protocolo MySQL/MariaDB sobre TCP.

![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu_22.04-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![MariaDB](https://img.shields.io/badge/MariaDB_10.6-003545?style=for-the-badge&logo=mariadb&logoColor=white)
![Java](https://img.shields.io/badge/Java_21_(Temurin)-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)
![CloudBeaver](https://img.shields.io/badge/CloudBeaver_26.x-00AEEF?style=for-the-badge&logo=dbeaver&logoColor=white)

---

## Tabla de contenidos

- [Información general](#información-general)
- [Tecnologías utilizadas](#tecnologías-utilizadas)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Requisitos previos](#requisitos-previos)
- [Cómo levantar los servicios](#cómo-levantar-los-servicios)
- [Descripción de los Dockerfiles](#descripción-de-los-dockerfiles)
- [Conectar CloudBeaver al servidor](#conectar-cloudbeaver-al-servidor)
- [Captura de tráfico de red](#captura-de-tráfico-de-red)
- [Cómo detener los servicios](#cómo-detener-los-servicios)
- [Autores](#autores)

---

## Información general

Este proyecto implementa una arquitectura cliente-servidor de base de datos completamente contenerizada con Docker. El objetivo es observar y analizar el protocolo **MySQL** (utilizado por MariaDB) operando sobre la capa de transporte TCP, dentro de una red virtual Docker tipo bridge.

- El **servidor** ejecuta MariaDB 10.6 instalado desde `apt` sobre Ubuntu 22.04.
- El **cliente** ejecuta CloudBeaver (interfaz web de DBeaver) sobre Ubuntu 22.04, obtenido mediante build multi-stage.
- Ambos contenedores se comunican a través de la red `db_network` y el tráfico entre ellos puede ser capturado con `tcpdump` para su análisis.

---

## Tecnologías utilizadas

| Tecnología | Versión | Rol |
|---|---|---|
| Docker Desktop | 4.x+ | Motor de contenedores |
| Docker Compose | v2 | Orquestación de servicios |
| Ubuntu | 22.04 LTS | Base de ambas imágenes |
| MariaDB | 10.6.x | Motor de base de datos (servidor) |
| Java (Temurin) | 21 | Runtime para CloudBeaver |
| CloudBeaver CE | 26.x | Cliente web de base de datos |

---

## Estructura del proyecto

```
Tarea2TallerDeRedes/
│
├── docker-compose.yml          # Orquesta ambos servicios, la red y el volumen
│
├── servidor/
│   ├── Dockerfile              # Imagen del servidor: ubuntu:22.04 + MariaDB
│   ├── init.sql                # Crea la BD, el usuario y los permisos al iniciar
│   └── entrypoint.sh           # Script de arranque: inicializa y lanza mariadbd
│
└── cliente/
    └── Dockerfile              # Imagen del cliente: ubuntu:22.04 + Java 21 + CloudBeaver
```

### Descripción de archivos clave

| Archivo | Descripción |
|---|---|
| `docker-compose.yml` | Define los dos servicios (`servidor`, `cliente`), la red `db_network` (bridge) y el volumen `mariadb_data` para persistir los datos |
| `servidor/Dockerfile` | Parte de `ubuntu:22.04`, instala `mariadb-server` con `apt`, configura `bind-address = 0.0.0.0` y copia los scripts de inicio |
| `servidor/init.sql` | SQL ejecutado en el primer arranque: crea la base de datos `taller_redes` y el usuario `usuario` con todos los privilegios |
| `servidor/entrypoint.sh` | Reemplaza a `systemctl`: inicializa el directorio de datos, ejecuta `init.sql` y lanza `mariadbd` en foreground |
| `cliente/Dockerfile` | Parte de `ubuntu:22.04`; usa build multi-stage para copiar Java 21 y CloudBeaver desde la imagen oficial de DBeaver |

---

## Requisitos previos

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) instalado y en ejecución
- Docker Compose v2 (incluido en Docker Desktop)
- Puerto `3307` y `8978` disponibles en el host

> **Nota:** El servidor se expone en el puerto `3307` del host (no `3306`) porque ese puerto puede estar ocupado por una instalación local de MySQL/MariaDB.

---

## Cómo levantar los servicios

Desde la raíz del proyecto (`Tarea2TallerDeRedes/`):

**1. Construir las imágenes e iniciar los contenedores en segundo plano:**

```bash
docker compose up -d
```

Docker construirá ambas imágenes desde sus respectivos `Dockerfile` y levantará los contenedores. En el primer arranque, `entrypoint.sh` inicializará la base de datos y ejecutará `init.sql` automáticamente.

**2. Verificar que ambos contenedores estén corriendo:**

```bash
docker compose ps
```

Salida esperada:

```
NAME                 IMAGE                STATUS         PORTS
cloudbeaver_client   desktop-cliente      Up X seconds   0.0.0.0:8978->8978/tcp
mariadb_server       desktop-servidor     Up X seconds   0.0.0.0:3307->3306/tcp
```

**3. Ver los logs en tiempo real (opcional):**

```bash
docker compose logs -f
```

---

## Descripción de los Dockerfiles

### `servidor/Dockerfile`

```
Base:      ubuntu:22.04
Instala:   mariadb-server (via apt-get)
Configura: bind-address = 0.0.0.0 (acepta conexiones remotas)
Copia:     init.sql → /docker-entrypoint-initdb.d/
           entrypoint.sh → /entrypoint.sh
Puerto:    EXPOSE 3306
CMD:       ["/entrypoint.sh"]
```

- **No usa `systemctl`** (no hay systemd en el contenedor). En su lugar, `entrypoint.sh` inicia `mariadbd` directamente en foreground con `exec mariadbd --user=mysql`.
- La técnica `bind-address = 0.0.0.0` es necesaria para que el cliente (en otro contenedor) pueda conectarse vía TCP.

### `cliente/Dockerfile`

```
Base:      ubuntu:22.04
Instala:   wget, unzip, curl (via apt-get)
Multi-stage:
  ├── COPY --from=dbeaver/cloudbeaver:latest /opt/java/openjdk → /opt/java/openjdk
  └── COPY --from=dbeaver/cloudbeaver:latest /opt/cloudbeaver  → /opt/cloudbeaver
Configura: JAVA_HOME=/opt/java/openjdk
Puerto:    EXPOSE 8978
CMD:       ["./run-cloudbeaver-server.sh"]
```

- CloudBeaver CE no distribuye binarios independientes para Linux; su única distribución oficial es la imagen Docker. Se utiliza **build multi-stage** (`COPY --from`) para extraer los archivos de la imagen oficial y colocarlos sobre la base `ubuntu:22.04`, sin que la imagen de DBeaver forme parte de la imagen final.
- Se copia Java 21 (Temurin) desde la misma imagen fuente, ya que CloudBeaver 26.x requiere Java 21 y Ubuntu 22.04 solo incluye Java 17 en sus repositorios oficiales.

---

## Conectar CloudBeaver al servidor

**1.** Abrir el navegador y navegar a:

```
http://localhost:8978
```

**2.** En la pantalla de bienvenida, crear una nueva conexión y seleccionar **MariaDB**.

**3.** Completar los parámetros de conexión:

| Campo | Valor |
|---|---|
| Host | `mariadb_server` |
| Port | `3306` |
| Database | `taller_redes` |
| Username | `usuario` |
| Password | `usuario_password` |

> El host es `mariadb_server` (el `container_name` del servidor), no `localhost`. Ambos contenedores están en la red `db_network` y Docker resuelve ese nombre automáticamente.

**4.** Hacer clic en **Test Connection** y luego en **Finish**.

---

## Captura de tráfico de red

Para capturar el tráfico MySQL entre los contenedores se utiliza la imagen `nicolaka/netshoot`, que incluye `tcpdump` y otras herramientas de diagnóstico de red.

**Unir netshoot al namespace de red del servidor y capturar tráfico en el puerto 3306:**

```bash
docker run -it --rm \
  --net container:mariadb_server \
  nicolaka/netshoot \
  tcpdump -i any port 3306 -nn -A
```

| Flag | Significado |
|---|---|
| `--net container:mariadb_server` | Comparte el namespace de red del contenedor del servidor |
| `-i any` | Escucha en todas las interfaces de red |
| `port 3306` | Filtra solo tráfico MySQL |
| `-nn` | No resuelve IPs ni puertos a nombres |
| `-A` | Muestra el contenido de los paquetes en ASCII |

Mientras este comando está corriendo, ejecutar una consulta desde CloudBeaver para observar los paquetes del protocolo MySQL en la salida.

---

## Cómo detener los servicios

**Detener y eliminar los contenedores** (los datos persisten en el volumen):

```bash
docker compose down
```

**Detener, eliminar contenedores Y borrar el volumen de datos** (elimina la base de datos):

```bash
docker compose down -v
```

**Reconstruir las imágenes desde cero** (útil si se modificaron los Dockerfiles):

```bash
docker compose up -d --build
```

---

## Autores

Desarrollado como parte de la asignatura **Taller de Redes**.

| Nombre | GitHub |
|---|---|
| Joaquin Utreras | [@jokuum](https://github.com/jokuum) |
| Juan Pablo Ugaz | — |
