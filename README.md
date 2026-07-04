# Tarea 2 y 3 — Taller de Redes

> **Tarea 2:** Despliegue contenerizado de un servidor MariaDB y un cliente web CloudBeaver utilizando Docker Compose, con análisis del protocolo MySQL/MariaDB sobre TCP.
>
> **Tarea 3:** Interceptación, inyección y modificación del tráfico MySQL con **Scapy + NFQUEUE**, análisis de métricas de red (delay y packet loss) y hallazgo de sus cotas de desempeño.

![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu_22.04-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![MariaDB](https://img.shields.io/badge/MariaDB_10.6-003545?style=for-the-badge&logo=mariadb&logoColor=white)
![Java](https://img.shields.io/badge/Java_21_(Temurin)-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)
![CloudBeaver](https://img.shields.io/badge/CloudBeaver_26.x-00AEEF?style=for-the-badge&logo=dbeaver&logoColor=white)
![Python](https://img.shields.io/badge/Python_3-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-000000?style=for-the-badge&logo=python&logoColor=white)

---

## Tabla de contenidos

### Parte 1 — Tarea 2 (infraestructura)
- [Información general](#información-general)
- [Tecnologías utilizadas](#tecnologías-utilizadas)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Requisitos previos](#requisitos-previos)
- [Cómo levantar los servicios](#cómo-levantar-los-servicios)
- [Descripción de los Dockerfiles](#descripción-de-los-dockerfiles)
- [Conectar CloudBeaver al servidor](#conectar-cloudbeaver-al-servidor)
- [Captura de tráfico de red](#captura-de-tráfico-de-red)
- [Cómo detener los servicios](#cómo-detener-los-servicios)

### Parte 2 — Tarea 3 (interceptación y métricas con Scapy)
- [Objetivo de la Tarea 3](#objetivo-de-la-tarea-3)
- [Arquitectura del entorno de ataque](#arquitectura-del-entorno-de-ataque)
- [El servicio scapy y su Dockerfile](#el-servicio-scapy-y-su-dockerfile)
- [El protocolo MySQL: estructura del paquete](#el-protocolo-mysql-estructura-del-paquete)
- [Scripts desarrollados](#scripts-desarrollados)
- [Actividad 1 — Interceptación del tráfico](#actividad-1--interceptación-del-tráfico)
- [Actividad 2 — Modificaciones de campos del protocolo](#actividad-2--modificaciones-de-campos-del-protocolo)
- [Actividad 3 — Inyección de tráfico por fuzzing](#actividad-3--inyección-de-tráfico-por-fuzzing)
- [Actividad 4 — Métricas de red y cotas de desempeño](#actividad-4--métricas-de-red-y-cotas-de-desempeño)
- [Inventario de archivos de la Tarea 3](#inventario-de-archivos-de-la-tarea-3)

### Otros
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
├── docker-compose.yml          # Orquesta los 3 servicios, la red y el volumen
│
├── servidor/                   # ── Tarea 2 ──
│   ├── Dockerfile              # Imagen del servidor: ubuntu:22.04 + MariaDB
│   ├── init.sql                # Crea la BD, el usuario y los permisos al iniciar
│   └── entrypoint.sh           # Script de arranque: inicializa y lanza mariadbd
│
├── cliente/                    # ── Tarea 2 ──
│   └── Dockerfile              # Imagen del cliente: ubuntu:22.04 + Java 21 + CloudBeaver
│
├── db/                         # ── Tarea 3 ──
│   └── schema_taller_redes.sql # Esquema de la BD taller_redes (usuarios, posts, comentarios, likes)
│
└── scapy/                      # ── Tarea 3 ──
    ├── Dockerfile              # Imagen de ataque: ubuntu:22.04 + Scapy + NFQUEUE + netem
    ├── INFORME_CONTENIDO.md    # Material completo para el informe de la Tarea 3
    └── scripts/                # Scripts montados en /scripts dentro del contenedor
        ├── sniffer.py          # Captura y parseo del header MySQL → .pcap + log
        ├── sniff_test.py       # Prueba de humo (solo observa)
        ├── mitm_nfqueue.py     # Las 3 modificaciones de campos (comando/largo/seq_id)
        ├── fuzzing.py          # Las 2 inyecciones por fuzzing
        ├── arp_spoof.py        # Estrategia B (ARP spoofing) — explorada, NO ejecutada
        ├── captura_mysql.pcap  # Evidencia de captura (abrible en Wireshark)
        ├── log_*.txt           # Logs de captura, mitm y fuzzing
        └── metricas/           # Barrido de métricas y gráficos
            ├── barrido.py      # Aplica tc netem, mide throughput, exporta CSV
            ├── graficar.py     # Genera los gráficos métrica vs throughput
            ├── resultados_*.csv          # Datos crudos de delay y loss
            └── *_vs_throughput.png       # Gráficos generados
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

# Parte 2 — Tarea 3

> Interceptación, inyección y modificación del tráfico MySQL con **Scapy + NFQUEUE**, y análisis de métricas de red con sus cotas de desempeño. Toda la fundamentación, los datos crudos y el material para el informe están en [`scapy/INFORME_CONTENIDO.md`](scapy/INFORME_CONTENIDO.md).

---

## Objetivo de la Tarea 3

Sobre el mismo servicio de base de datos de la Tarea 2 (MariaDB + CloudBeaver, protocolo **MySQL wire protocol en claro, sin TLS**), analizar qué le ocurre al servicio al **inyectar o modificar tráfico no esperado** y al **degradar las métricas de red**, usando **Scapy**. En concreto:

1. **Interceptar** el tráfico MySQL cliente↔servidor.
2. Realizar **2 inyecciones** de tráfico mediante **fuzzing**.
3. Realizar **3 modificaciones** de campos del protocolo, con su fundamentación.
4. Elegir **2 métricas de red** (distintas de throughput/goodput), hallar su **cota de desempeño** y graficar **métrica vs throughput**.

La base de datos `taller_redes` modela una mini red social con 4 tablas (`usuarios`, `posts`, `comentarios`, `likes`) definidas en [`db/schema_taller_redes.sql`](db/schema_taller_redes.sql).

---

## Arquitectura del entorno de ataque

Al `docker-compose.yml` se le agregó un tercer contenedor de ataque, **`scapy_mitm`**.

### Estrategia A — namespace compartido (implementada)

El contenedor `scapy_mitm` usa `network_mode: "service:cliente"`, es decir **comparte la pila de red completa del cliente CloudBeaver** (misma interfaz `eth0`, misma IP, mismas cadenas `iptables`). Consecuencia clave: **todo el tráfico MySQL cliente↔servidor atraviesa la propia netns de `scapy_mitm`**, sin necesidad de ARP spoofing.

Sobre esa base, el tráfico se redirige a una cola **NFQUEUE** con reglas `iptables`:

```bash
iptables -A OUTPUT -p tcp --dport 3306 -j NFQUEUE --queue-num 1
iptables -A INPUT  -p tcp --sport 3306 -j NFQUEUE --queue-num 1
```

Scapy toma cada paquete de la cola, lo inspecciona/modifica y lo reinyecta.

```
┌──────────────────────────── red bridge db_network ────────────────────────────┐
│                                                                                │
│   cloudbeaver_client (172.18.0.3)              mariadb_server (172.18.0.2)      │
│   ┌───────────────────────────────┐            ┌─────────────────────────┐     │
│   │  CloudBeaver  :8978            │  MySQL     │  MariaDB  :3306          │     │
│   │  ┌─────────────────────────┐  │◄──3306────►│                         │     │
│   │  │ scapy_mitm (misma netns)│  │            └─────────────────────────┘     │
│   │  │  NFQUEUE ← iptables      │  │                                            │
│   │  └─────────────────────────┘  │                                            │
│   └───────────────────────────────┘                                            │
└────────────────────────────────────────────────────────────────────────────────┘
```

- Capacidades del contenedor: `NET_ADMIN` (iptables, netem) y `NET_RAW` (raw sockets / NFQUEUE).
- IPs observadas: cliente `172.18.0.3`, servidor `172.18.0.2`, puerto MySQL `3306`.

### Estrategia B — ARP spoofing (explorada y descartada)

Se evaluó colocar Scapy como **tercer nodo independiente** en `db_network` y envenenar las cachés ARP de cliente y servidor (MITM clásico). **No se implementó** porque con `network_mode: "service:cliente"` no existe un "medio" en el cual insertarse (un contenedor no puede ARP-spoofearse a sí mismo), y la Estrategia A ya cubre todos los requisitos. El script [`scapy/scripts/arp_spoof.py`](scapy/scripts/arp_spoof.py) se conserva como constancia del análisis, **no ejecutado**.

---

## El servicio scapy y su Dockerfile

El servicio se levanta junto al resto con `docker compose up -d --build`. El contenedor queda vivo con `tail -f /dev/null` y los scripts se lanzan manualmente:

```bash
docker exec -it scapy_mitm python3 /scripts/<script>.py
```

**`scapy/Dockerfile`** parte de `ubuntu:22.04` e instala, entre otros:

| Herramienta | Rol |
|---|---|
| `python3` + `scapy` (pip) | Manipulación de paquetes |
| `NetfilterQueue` (pip) | Binding de NFQUEUE para interceptar/reinyectar |
| `iptables` | Redirigir el tráfico 3306 a la cola NFQUEUE |
| `iproute2` (`tc` / `netem`) | Inyectar delay y packet loss para las métricas |
| `tcpdump` / `tshark` | Verificar y depurar la captura |
| `mariadb-client` | Carga de trabajo del barrido de métricas |
| `matplotlib` (pip) | Gráficos métrica vs throughput |

---

## El protocolo MySQL: estructura del paquete

Todo mensaje del protocolo MySQL comienza con un **header fijo de 5 bytes**:

```
+-------------------+----------------+---------------+------------------+
| largo (3 bytes)   | sequence_id    | comando       | cuerpo...        |
| little-endian     | (1 byte)       | (1 byte)      | (query en texto) |
+-------------------+----------------+---------------+------------------+
```

- **largo:** longitud del cuerpo, little-endian (3 bytes → hasta 16 MB).
- **sequence_id:** número de secuencia dentro de un mismo comando; arranca en 0 y se incrementa de a 1.
- **comando:** `0x03` = COM_QUERY, `0x02` = COM_INIT_DB, `0x01` = COM_QUIT.
- En **respuestas del servidor**, el 5º byte es el primer byte del cuerpo: `0x00` = OK, `0xFF` = ERROR, `0xFE` = EOF.

Todas las modificaciones/inyecciones direccionan estos bytes **por posición**, lo que permite tocar `comando`, `largo` o `sequence_id` de forma determinística.

---

## Scripts desarrollados

Todos en [`scapy/scripts/`](scapy/scripts/) (montados en `/scripts` dentro del contenedor):

| Script | Rol |
|---|---|
| `sniffer.py` | Captura definitiva: filtra `tcp port 3306`, parsea el header MySQL, clasifica cada paquete y persiste evidencia a `.pcap` + log. |
| `sniff_test.py` | Prueba de humo (solo observa, confirma que el tráfico pasa por la netns). |
| `mitm_nfqueue.py` | Las **3 modificaciones** de campos vía NFQUEUE (se elige una con la constante `MODO`). |
| `fuzzing.py` | Las **2 inyecciones** por fuzzing vía NFQUEUE (se elige con `--modo`). |
| `metricas/barrido.py` | Aplica `tc netem` (delay o loss), corre la carga fija, mide throughput aplicativo, detecta la cota y exporta CSV. |
| `metricas/graficar.py` | Genera el gráfico métrica vs throughput marcando la cota. |
| `arp_spoof.py` | Estrategia B — diseño explorado, **NO ejecutado**. |

> Al modificar un payload se ejecuta `del ip[IP].len, ip[IP].chksum, ip[TCP].chksum` antes de reinyectar, para forzar el recálculo de checksums de IP y TCP.

---

## Actividad 1 — Interceptación del tráfico

**Script:** `sniffer.py`

```bash
docker exec -it scapy_mitm python3 /scripts/sniffer.py --duracion 90
```

Mientras corre, se ejecutan queries reales desde CloudBeaver. En una corrida representativa de 90 s: **24 paquetes** (8 queries, 8 resultsets, 8 ACKs). Se generó evidencia en [`captura_mysql.pcap`](scapy/scripts/captura_mysql.pcap) (Wireshark) y [`log_captura.txt`](scapy/scripts/log_captura.txt).

Extracto real del log (header parseado por posición, queries en claro):

```
tipo=query     | seq=  0 | byte5=0x03 | largo=36  | data=b'SELECT * FROM usuarios\nLIMIT 0, 200'
tipo=resultset | seq=  1 | byte5=0x04 | largo=1   | data=b'7\x00\x00\x02\x03def...'
tipo=query     | seq=  0 | byte5=0x03 | largo=65  | data=b"UPDATE usuarios SET email = '...' WHERE id..."
```

---

## Actividad 2 — Modificaciones de campos del protocolo

Con `mitm_nfqueue.py`, seleccionando una modificación por vez con `MODO`. Actúa solo sobre paquetes **COM_QUERY (0x03)** del cliente. Evidencia en [`log_mitm.txt`](scapy/scripts/log_mitm.txt).

| Mod | Campo | Cambio | Esperado | Observado | ¿Coincide? |
|-----|-------|--------|----------|-----------|:---------:|
| A | `comando` | `0x03→0x02` | `ERROR 1049 Unknown database` (el cuerpo se lee como nombre de BD) | Error en CloudBeaver | ✅ |
| B | `largo` | `33→83` (+50) | Timeout de aplicación (el servidor espera bytes que no llegan) | Cuelgue "Loading…" indefinido | ✅ |
| C | `sequence_id` | `0→5` | Error "Got packets out of order" + cierre | Cuelgue **sin** error explícito | ❌ (ver hipótesis) |

- **Mod A:** el byte de comando determina por completo la semántica del mismo cuerpo: la misma query, reetiquetada como `COM_INIT_DB`, pasa a ser un nombre de BD inválido.
- **Mod B:** al recalcular checksums pero **no** los números de secuencia TCP, el desajuste no rompe TCP; el servidor cuenta los bytes declarados y se bloquea esperando el cuerpo → timeout de aplicación (comportamiento esperado).
- **Mod C (hipótesis):** al recibir `seq=5` cuando esperaba `seq=0`, MariaDB interpreta que se "perdieron" los paquetes 0–4 y se queda esperándolos, en vez de rechazar el paquete de inmediato. Mismo mecanismo de fondo que la Mod B.

---

## Actividad 3 — Inyección de tráfico por fuzzing

Con `fuzzing.py`. A diferencia de las modificaciones (que alteran un campo válido), el fuzzing **inyecta contenido malformado/aleatorio** reemplazando el payload de un COM_QUERY real. Evidencia en [`log_fuzzing.txt`](scapy/scripts/log_fuzzing.txt).

| Inyección | Comando | Técnica | Esperado | Observado |
|-----------|---------|---------|----------|-----------|
| 1 | `--modo comando` | Byte de comando aleatorio fuera de rango (`0x4b`) | `ERROR 1047 Unknown command` | ✅ `ERROR 1047` confirmado |
| 2 | `--modo largo` | Largo declarado 16 MB, cuerpo real de 10 B | Timeout de aplicación | No determinista: **cuelgue** o `ERROR 1047` |

- **Inyección 1:** el servidor falla de forma **controlada** (devuelve un ERROR packet bien formado, sin crashear). Prueba de robustez del parser de comandos.
- **Inyección 2 (hipótesis):** el primer byte aleatorio del cuerpo cae en la posición del byte de comando; según su valor, el servidor responde `ERROR 1047` de inmediato **o** se cuelga esperando los 16 MB declarados. La variabilidad es consecuencia directa de la aleatoriedad del fuzzing.

Ejemplo de ERROR packet capturado (inyección 1):

```
[FUZZ comando] #1 inyectado | comando=0x4b largo_real=16
[RESP servidor] ERROR packet: 18000001ff1704233038533031556e6b6e6f776e20636f6d6d616e64
→ ERROR 1047 (08S01): Unknown command
```

---

## Actividad 4 — Métricas de red y cotas de desempeño

Se eligieron **dos métricas distintas de throughput/goodput**, inyectadas con `tc` + `netem` sobre `eth0`. La **cota de desempeño** es el primer valor de la métrica donde la carga deja de completar. El throughput medido es **aplicativo** (bytes de payload MySQL / duración). Herramientas: `metricas/barrido.py` (mide y exporta CSV) y `metricas/graficar.py` (genera el PNG).

### Métrica 1 — Latencia / delay (tiempo)

```bash
python3 /scripts/metricas/barrido.py --metrica delay --valores 0 200 800 1600 2400 3000 4000 5000
```

| delay (ms) | throughput (bps) | estado |
|-----------:|-----------------:|--------|
| 0 | 615.796 | ok |
| 200 | 11.614 | ok |
| 2400 | 1.101 | ok |
| **3000** | 917 | **fallo** |
| 5000 | 230 | fallo |

**Cota: ~3000 ms.** Hasta 2400 ms la query completa (9,6 s); a 3000 ms supera el timeout de 10 s. La cota es baja porque **cada query MySQL implica ~4 round-trips** (handshake + auth + query + resultado), y cada uno paga el delay. Datos en [`resultados_delay.csv`](scapy/scripts/metricas/resultados_delay.csv), gráfico en [`delay_vs_throughput.png`](scapy/scripts/metricas/delay_vs_throughput.png).

### Métrica 2 — Packet loss (confiabilidad)

```bash
python3 /scripts/metricas/barrido.py --metrica loss --valores 0 1 5 10 20 40 60
```

| loss (%) | throughput (bps) | estado |
|---------:|-----------------:|--------|
| 0 | 647.887 | ok |
| 1 | 708.567 | ok |
| 5 | 99.078 | ok |
| 40 | 6.277 | ok |
| **60** | 1.553 | **degradado** |

**Cota: ~40–60 % (difusa).** Con solo **5 %** de pérdida el throughput se desploma −85 % por las **retransmisiones TCP con backoff exponencial** (cada paquete perdido espera el RTO antes de reenviar). La cota es un rango difuso porque la pérdida es **probabilística** (netem descarta al azar). Datos en [`resultados_loss.csv`](scapy/scripts/metricas/resultados_loss.csv), gráfico en [`loss_vs_throughput.png`](scapy/scripts/metricas/loss_vs_throughput.png).

### Comparación

| Aspecto | Delay (tiempo) | Loss (confiabilidad) |
|---------|----------------|----------------------|
| Naturaleza | Determinista | Estocástica |
| Cota | Nítida: ~3000 ms | Difusa: ~40–60 % |
| Mecanismo | Round-trips del protocolo | Retransmisiones TCP + RTO |
| Curva | Caída 1/x suave | Caída abrupta ya en 5 % |

---

## Inventario de archivos de la Tarea 3

**Scripts:** `sniffer.py`, `sniff_test.py`, `mitm_nfqueue.py`, `fuzzing.py`, `arp_spoof.py`, `metricas/barrido.py`, `metricas/graficar.py`.

**Evidencia generada:** `captura_mysql.pcap`, `log_captura.txt`, `log_mitm.txt`, `log_fuzzing.txt`, `metricas/resultados_delay.csv`, `metricas/resultados_loss.csv`, `metricas/delay_vs_throughput.png`, `metricas/loss_vs_throughput.png`.

**Infraestructura:** `docker-compose.yml` (3 servicios), `scapy/Dockerfile`, `db/schema_taller_redes.sql`.

**Informe:** todo el contenido, datos y fundamentaciones para el informe LaTeX están en [`scapy/INFORME_CONTENIDO.md`](scapy/INFORME_CONTENIDO.md).

---

## Autores

Desarrollado como parte de la asignatura **Taller de Redes**.

| Nombre | GitHub |
|---|---|
| Joaquin Utreras | [@jokuum](https://github.com/jokuum) |
| Juan Pablo Ugaz | [@jotaRacer](https://github.com/jotaRacer) |
