# Contenido para el informe — Tarea 3 (Taller de Redes)

> **Instrucciones para el agente de LaTeX.** Este documento contiene TODO el
> contenido, datos y contexto necesarios para redactar el informe completo de la
> Tarea 3 en LaTeX. Vos NO tenés contexto previo del proyecto: acá está todo.
> Tu trabajo es transformar este material en un informe académico formal,
> bien estructurado, con secciones numeradas, tablas, figuras (los PNG están
> referenciados con su ruta), bloques de código/hexdumps y las fundamentaciones
> pedidas. No inventes datos: todos los valores, logs y resultados de acá son
> reales y provienen de la ejecución. Donde diga `[COMPLETAR: ...]` es un dato
> que deben llenar los integrantes (nombres, fecha, link del video).

---

## 0. Metadatos del informe

- **Asignatura:** Taller de Redes
- **Tarea:** Tarea 3 — Interceptación, inyección y modificación de tráfico con Scapy; análisis de métricas de red y cotas de desempeño.
- **Integrantes:** `[COMPLETAR: nombres y roles de los 2 integrantes]`
- **Repositorio:** GitLab de la Tarea 2 (mismo repo). `[COMPLETAR: URL]`
- **Video (6–8 min):** `[COMPLETAR: URL público]`
- **Fecha de ejecución de los experimentos:** 3 de julio de 2026.

---

## 1. Contexto y punto de partida (viene de la Tarea 2)

En la Tarea 2, el grupo montó con **Docker Compose** un servicio de base de datos
compuesto por dos aplicaciones:

- **Servidor:** **MariaDB** (contenedor `mariadb_server`), escuchando en el puerto
  estándar **3306** de MySQL/MariaDB. Base de datos `taller_redes`.
- **Cliente:** **CloudBeaver** (contenedor `cloudbeaver_client`), interfaz web de
  administración de bases de datos servida en el puerto **8978**, que se conecta
  al servidor por el puerto 3306.

El **protocolo específico** que usa este servicio es el **MySQL Client/Server
Protocol** (también llamado "MySQL wire protocol"), que en este laboratorio viaja
**en claro (sin TLS)**, lo que permite interceptarlo y modificarlo.

La base de datos `taller_redes` modela una mini red social con 4 tablas:
`usuarios`, `posts`, `comentarios`, `likes` (con claves foráneas entre ellas).
Las queries usadas en los experimentos operan sobre estas tablas (ej.
`SELECT * FROM usuarios`, `SELECT * FROM posts`, un JOIN de posts con conteo de
likes, etc.).

### Objetivo de la Tarea 3
Analizar qué le ocurre al servicio de red al **inyectar o modificar tráfico no
esperado** (por parte del cliente o del servidor) y al **modificar métricas de
red**, usando **Scapy**. En concreto:
1. Interceptar el tráfico MySQL cliente↔servidor.
2. Dos **inyecciones** de tráfico mediante **fuzzing**.
3. Tres **modificaciones** de campos del protocolo, con fundamentación.
4. Elegir **dos métricas de red** (≠ throughput/goodput), hallar su **cota de
   desempeño** y graficar **métrica vs throughput**.

---

## 2. Arquitectura del entorno de ataque

Se agregó al `docker-compose.yml` un tercer contenedor de ataque:

- **`scapy_mitm`**: contenedor Ubuntu 22.04 con **Scapy** (última versión vía
  pip), **NetfilterQueue (NFQUEUE)**, `iptables`, `tc`/`netem` (paquete
  `iproute2`), `tcpdump`/`tshark`, `mariadb-client` y `matplotlib`.

### Decisión de topología: Estrategia A (namespace compartido)
El contenedor `scapy_mitm` usa `network_mode: "service:cliente"`, es decir
**comparte la pila de red completa del cliente CloudBeaver** (misma interfaz
`eth0`, misma IP, mismas cadenas `iptables`). Consecuencia clave: **todo el
tráfico MySQL cliente↔servidor atraviesa la propia netns de `scapy_mitm`**, sin
necesidad de ARP spoofing.

Sobre esa base se interceptó/modificó el tráfico redirigiéndolo a una cola
**NFQUEUE** con reglas `iptables`:
```
iptables -A OUTPUT -p tcp --dport 3306 -j NFQUEUE --queue-num 1
iptables -A INPUT  -p tcp --sport 3306 -j NFQUEUE --queue-num 1
```
Scapy toma cada paquete de la cola, lo inspecciona/modifica y lo reinyecta.

- IPs observadas en los experimentos: **cliente `172.18.0.3`**, **servidor
  `172.18.0.2`**, puerto MySQL `3306`.
- Capacidades del contenedor: `NET_ADMIN` (iptables, netem) y `NET_RAW` (raw
  sockets / NFQUEUE).

> **Nota para el informe:** conviene incluir un diagrama de la topología: tres
> contenedores en la red bridge `db_network`, con `scapy_mitm` fusionado a la
> pila de red de `cloudbeaver_client`, y la cola NFQUEUE interceptando el 3306.

### Estrategia B evaluada y descartada (ARP spoofing)
Se evaluó una Estrategia B alternativa: colocar a Scapy como **tercer nodo
independiente** en la red `db_network` y envenenar las cachés ARP de servidor y
cliente para insertarse en el medio (MITM clásico). **Se decidió NO implementarla**
por:
1. El enunciado no pide comparar dos técnicas de MITM; la Estrategia A ya cubre
   todos los requisitos de fuzzing y modificación.
2. Conflicto estructural: con `network_mode: "service:cliente"`, `scapy_mitm`
   **ES** la misma pila de red que el cliente — no existe un "medio" en el que
   insertarse; un contenedor no puede ARP-spoofearse respecto de sí mismo. Para
   ejecutar la Estrategia B habría que reconvertir la topología a
   `networks: db_network`.
3. Riesgo de estado inconsistente cerca de la entrega (una restauración de ARP
   fallida cuelga la conexión).

El script `arp_spoof.py` se conserva en el repositorio como constancia del
análisis, comentado como "diseño explorado, no ejecutado". **No se grabó demo de
este script en el video.** (Incluir esta subsección en el informe demuestra que
la alternativa fue evaluada y entendida, no solo omitida.)

---

## 3. El protocolo MySQL: estructura del paquete (necesario para entender las modificaciones)

Todo mensaje del protocolo MySQL comienza con un **header fijo de 5 bytes**,
seguido del cuerpo:

```
+-------------------+----------------+---------------+------------------+
| largo (3 bytes)   | sequence_id    | comando       | cuerpo...        |
| little-endian     | (1 byte)       | (1 byte)      | (query en texto) |
+-------------------+----------------+---------------+------------------+
```

- **largo:** longitud del cuerpo que sigue, en little-endian (3 bytes → hasta 16 MB).
- **sequence_id:** número de secuencia del paquete dentro de un mismo comando;
  el servidor espera que arranque en 0 y se incremente de a 1.
- **comando:** tipo de mensaje. Valores relevantes:
  - `0x03` = **COM_QUERY** (ejecutar una query SQL en texto).
  - `0x02` = **COM_INIT_DB** (cambiar de base de datos; el cuerpo es un nombre de BD).
  - `0x01` = COM_QUIT.
- En las **respuestas del servidor**, el 5º byte NO es un comando sino el primer
  byte del cuerpo de respuesta: `0x00` = OK, `0xFF` = **ERROR packet**, `0xFE` =
  EOF, o el header de un resultset.

Todas las modificaciones e inyecciones de esta tarea se hacen **direccionando
estos bytes por posición** (no por búsqueda de texto), lo que permite tocar
`comando`, `largo` o `sequence_id` de forma determinística.

### Cómo leer un ERROR packet del servidor (aparece varias veces en los logs)
Ejemplo real capturado: `18 00 00 01 ff 17 04 23 30 38 53 30 31 55 6e 6b 6e 6f 77 6e 20 63 6f 6d 6d 61 6e 64`

| bytes | significado |
|-------|-------------|
| `18 00 00` | largo = 24 |
| `01` | sequence_id |
| `ff` | marcador de ERROR packet |
| `17 04` | código de error = 0x0417 = **1047** (little-endian) |
| `23` | `#` marcador de SQLSTATE |
| `30 38 53 30 31` | SQLSTATE = **"08S01"** |
| `55 6e...6e 64` | mensaje = **"Unknown command"** |

Es decir: **`ERROR 1047 (08S01): Unknown command`**.

---

## 4. Herramientas y scripts desarrollados

Todos los scripts están en `scapy/scripts/` (montado en `/scripts` dentro del
contenedor). Se ejecutan con `docker exec -it scapy_mitm python3 /scripts/<x>.py`.

| Script | Rol |
|--------|-----|
| `sniffer.py` | Captura definitiva: filtra `tcp port 3306`, parsea el header MySQL, clasifica cada paquete (handshake/query/resultset/error), y persiste evidencia a `.pcap` + log de texto. Exporta `parsear_mysql_header()`. |
| `sniff_test.py` | Prueba de humo (solo observa, confirma que el tráfico pasa por la netns). |
| `mitm_nfqueue.py` | Realiza las **3 modificaciones** de campos (comando/largo/sequence_id) vía NFQUEUE. Se selecciona una por vez con la constante `MODO`. |
| `fuzzing.py` | Realiza las **2 inyecciones** de fuzzing (comando aleatorio / largo inflado) vía NFQUEUE. Se selecciona con `--modo`. |
| `metricas/barrido.py` | Aplica `tc netem` (delay o loss), corre una carga de trabajo fija contra el servidor, mide el throughput aplicativo desde una captura viva, detecta la cota y exporta CSV. |
| `metricas/graficar.py` | Genera el gráfico métrica vs throughput (matplotlib) marcando la cota. |
| `arp_spoof.py` | Estrategia B — diseño explorado, NO ejecutado. |

**Detalle técnico común a las modificaciones/inyecciones:** al modificar el
payload se ejecuta `del ip[IP].len, ip[IP].chksum, ip[TCP].chksum` antes de
reinyectar, para forzar el **recálculo de checksums** de IP y TCP. Importante:
esto **no** ajusta los números de secuencia TCP (`seq`/`ack`) — lo cual es
relevante para la modificación de `largo` (ver §6.2).

---

## 5. Actividad 1 — Interceptación del tráfico (evidencia base)

**Script:** `sniffer.py`. **Comando:**
```
docker exec -it scapy_mitm python3 /scripts/sniffer.py --duracion 90
```
Mientras corría, se ejecutaron varias queries reales desde CloudBeaver.

**Resultado (resumen de una corrida representativa de 90 s):**
- 24 paquetes capturados: **8 queries**, **8 resultsets**, 8 ACKs puros (`otro`).
- Se generaron dos archivos de evidencia:
  - `scapy/scripts/captura_mysql.pcap` (abrible en Wireshark).
  - `scapy/scripts/log_captura.txt` (log de texto parseado).

**Extracto real del log de captura** (`log_captura.txt`), que muestra el parseo
del header por posición y el texto de las queries en claro:
```
tipo=query     | seq=  0 | byte5=0x03 | largo=36  | data=b'SELECT * FROM usuarios\nLIMIT 0, 200'
tipo=resultset | seq=  1 | byte5=0x04 | largo=1   | data=b'7\x00\x00\x02\x03def\x0ctaller_redes\x08usuarios...'
tipo=query     | seq=  0 | byte5=0x03 | largo=133 | data=b'SELECT p.id, u.username, p.contenido, p.fecha\nFROM posts p\nJ...'
tipo=query     | seq=  0 | byte5=0x03 | largo=65  | data=b"UPDATE usuarios SET email = 'ana_nueva@example.com' WHERE id..."
tipo=resultset | seq=  1 | byte5=0x00 | largo=48  | data=b'\x01\x00\x02\x00\x00\x00(Rows matched: 1  Changed: 1  Warnings: 0'
```

**Conclusión de la actividad:** se confirma que, al compartir la netns del
cliente, Scapy ve todo el tráfico MySQL en claro, puede parsear el header de 5
bytes por posición y clasificar los mensajes por tipo. Esta captura es la base de
evidencia reutilizada en el resto de la tarea.

> **Nota metodológica (incluir en el informe):** en algunas corridas el conteo de
> `handshake` fue 0, porque CloudBeaver mantiene la conexión abierta (connection
> pooling) y el greeting inicial ocurre antes de arrancar el sniffer. Para
> capturar el handshake habría que reiniciar `cloudbeaver_client` y arrancar el
> sniffer antes de la primera conexión.

---

## 6. Actividad 2 — Tres modificaciones de campos del protocolo

Se usó `mitm_nfqueue.py`, seleccionando una modificación por vez con la constante
`MODO`. Cada modificación actúa solo sobre paquetes **COM_QUERY (0x03)** del
cliente. Los eventos quedaron registrados en `scapy/scripts/log_mitm.txt`.

Para cada una se documenta: **qué se modificó**, **comportamiento esperado**,
**comportamiento observado** e **hipótesis** cuando no coincidieron (como pide el
enunciado).

### 6.1 Modificación A — Campo `comando` (0x03 → 0x02)
**Qué hace:** cambia el byte de comando de `0x03` (COM_QUERY) a `0x02`
(COM_INIT_DB). Con esto, el servidor deja de interpretar el cuerpo como una query
SQL y lo interpreta como un **nombre de base de datos** al que conectarse.

**Evidencia (log real, `log_mitm.txt`):**
```
[MOD comando] 0x03 -> 0x02 | seq=0 | query=b'SELECT * FROM usuarios\nLIMIT 0, 200'
```

**Comportamiento esperado:** el servidor recibe COM_INIT_DB con "nombre de BD"
= `"SELECT * FROM usuarios..."`, que no existe → responde **`ERROR 1049 Unknown
database`** y no ejecuta la query.

**Comportamiento observado:** `[COMPLETAR con la captura de CloudBeaver: el error
mostrado en la interfaz]`. Se esperaba `Unknown database`. Adjuntar screenshot de
CloudBeaver mostrando el error.

**Fundamentación:** el mismo texto que como COM_QUERY es una consulta válida, al
reetiquetarse como COM_INIT_DB pasa a ser un identificador de BD inválido; el
servidor cambia de "ejecutar SQL" a "seleccionar base de datos" y falla porque no
existe una base con ese nombre. Demuestra que el **byte de comando** determina
por completo la semántica del mismo cuerpo de datos.

### 6.2 Modificación B — Campo `largo` (33 → 83)
**Qué hace:** infla el largo declarado del cuerpo en +50 bytes, **sin** agregar
esos bytes reales. El header dice "vienen 83 bytes" pero solo se envían 33.

**Evidencia (log real, `log_mitm.txt`):**
```
[MOD largo] 33 -> 83 | seq=0
```

**Comportamiento esperado:** el servidor lee el largo declarado y **queda
esperando los bytes faltantes** que nunca llegan → **timeout de aplicación** (la
query nunca completa), no un error de protocolo inmediato.

**Comportamiento observado:** ✅ **confirmado**. La interfaz de CloudBeaver quedó
**colgada en estado "Loading…"** (adjuntar screenshot de CloudBeaver mostrando el
spinner "Loading…" indefinido). La conexión no cae por checksum inválido: el
stream TCP subyacente queda "sano", pero desincronizado a nivel de aplicación.

**Fundamentación / nota técnica clave:** la modificación recalcula los checksums
IP/TCP pero **no ajusta los números de secuencia TCP**. Por eso el desajuste no
se manifiesta como error TCP sino como una espera a nivel MySQL: el servidor,
siguiendo el protocolo, cuenta los bytes declarados y se bloquea esperando
completar el cuerpo. Es el comportamiento **esperado**, no un fallo del script.

### 6.3 Modificación C — Campo `sequence_id` (0 → 5)
**Qué hace:** desplaza el número de secuencia del paquete de 0 a 5, rompiendo el
orden que el servidor espera (un comando nuevo debe empezar en seq=0).

**Evidencia (log real, `log_mitm.txt`):**
```
[MOD sequence_id] 0 -> 5
```

**Comportamiento esperado:** el servidor detecta el paquete **fuera de secuencia**
y responde con un error de protocolo tipo **"Got packets out of order"**,
cerrando la conexión.

**Comportamiento observado:** ❌ **NO se dio el error esperado.** En su lugar, la
conexión **se colgó** (mismo síntoma que la Modificación B), sin mensaje de error
explícito.

**Hipótesis (requisito del enunciado ante comportamiento inesperado):** el
sequence_id debe incrementarse de a 1; al recibir seq=5 cuando esperaba seq=0, el
servidor MariaDB **interpreta que se "perdieron" los paquetes 0–4 y se queda
esperándolos** en lugar de rechazar el paquete de inmediato. El resultado es un
bloqueo por espera (equivalente a un timeout de aplicación), no un error de
protocolo inmediato. Es el mismo mecanismo de fondo que la Modificación B: el
servidor espera datos que nunca llegan.

### 6.4 Tabla resumen de las 3 modificaciones
| Mod | Campo | Cambio | Esperado | Observado | Coincide |
|-----|-------|--------|----------|-----------|----------|
| A | comando | 0x03→0x02 | ERROR 1049 Unknown database | `[COMPLETAR]` | `[COMPLETAR]` |
| B | largo | 33→83 (+50) | Timeout de aplicación | Cuelgue "Loading…" | ✅ Sí |
| C | sequence_id | 0→5 | Error "out of order" + cierre | Cuelgue (sin error) | ❌ No (ver hipótesis) |

---

## 7. Actividad 3 — Dos inyecciones de tráfico mediante fuzzing

Se usó `fuzzing.py`. A diferencia de las modificaciones (que alteran un campo
válido), el **fuzzing inyecta contenido malformado/aleatorio** reemplazando el
payload de un COM_QUERY real (vía NFQUEUE, para heredar los seq/ack de la
conexión TCP viva y no tener que reconstruir el handshake). Evidencia en
`scapy/scripts/log_fuzzing.txt`.

### 7.1 Inyección 1 — Fuzzing del campo `comando`
**Comando:** `python3 /scripts/fuzzing.py --modo comando`
**Qué hace:** genera un paquete con header coherente pero con el **byte de comando
tomando un valor aleatorio fuera del rango válido** (0x20–0xff; los comandos
válidos son 0x00–0x1f), más un cuerpo aleatorio.

**Evidencia (log real):**
```
[FUZZ comando] #1 inyectado | comando=0x4b largo_real=16
[RESP servidor] ERROR packet: 18000001ff1704233038533031556e6b6e6f776e20636f6d6d616e64
```
El error packet decodifica a **`ERROR 1047 (08S01): Unknown command`** (ver
tabla de decodificación en §3).

**Comportamiento esperado:** el servidor recibe un byte de comando inexistente
(0x4b = 75) → responde con **ERROR 1047 "Unknown command"** y no ejecuta nada.

**Comportamiento observado:** ✅ **confirmado literalmente.** El servidor devolvió
el error 1047 "Unknown command".

**Fundamentación:** demuestra que el servicio ante entrada no prevista **falla de
forma controlada** (devuelve un error de protocolo bien formado), sin crashear.
El fuzzing del byte de comando es una prueba de robustez del parser de comandos
del servidor.

### 7.2 Inyección 2 — Fuzzing del campo `largo`
**Comando:** `python3 /scripts/fuzzing.py --modo largo`
**Qué hace:** declara un largo enorme (`0xFFFFFF` = 16 MB) con un cuerpo real de
solo 10 bytes aleatorios.

**Evidencia (log real):**
```
[FUZZ largo] #1 inyectado | largo_declarado=0xFFFFFF largo_real=10   (22:11:45)  -> sin respuesta (cuelgue)
[FUZZ largo] #1 inyectado | largo_declarado=0xFFFFFF largo_real=10   (22:12:30)  -> ERROR 1047 Unknown command
```

**Comportamiento esperado:** con el largo declarado (16 MB) desacoplado del real
(10 B), el servidor queda esperando ~16 MB que nunca llegan → **timeout de
aplicación** (mismo mecanismo que la Modificación B, §6.2).

**Comportamiento observado:** **no determinista** — en un intento el servidor se
**colgó** (esperando los bytes), y en otro respondió **ERROR 1047 "Unknown
command"** de inmediato.

**Hipótesis (comportamiento inesperado / variable):** el cuerpo fuzzeado son 10
bytes aleatorios, y el **primero de ellos cae en la posición del byte de
comando** (5º byte del header). Según el valor aleatorio de ese byte y el orden
de lectura del servidor, se obtiene o bien un error de comando inválido (1047,
lectura rápida del comando) o bien una espera por los bytes declarados (cuelgue).
La variabilidad entre corridas es consecuencia directa de la aleatoriedad del
fuzzing y constituye un hallazgo válido: mezcla dos efectos (largo mentiroso +
comando aleatorio) en un mismo paquete.

### 7.3 Tabla resumen del fuzzing
| Inyección | Técnica | Esperado | Observado |
|-----------|---------|----------|-----------|
| 1 | comando aleatorio (0x4b) | ERROR 1047 Unknown command | ✅ ERROR 1047 |
| 2 | largo declarado 16 MB, cuerpo 10 B | Timeout de aplicación | No determinista: cuelgue **o** ERROR 1047 (ver hipótesis) |

---

## 8. Actividad 4 — Métricas de red, cotas de desempeño y gráficos

Se eligieron **dos métricas distintas de throughput/goodput, que miden aspectos
distintos de la red**:
- **Métrica 1 — Latencia / delay** (retardo): mide el **tiempo** de la red.
- **Métrica 2 — Packet loss** (pérdida): mide la **confiabilidad** del enlace.

Ambas se inyectaron con **`tc` + `netem`** sobre la interfaz `eth0` (compartida
con el cliente). La **cota de desempeño** se define como el primer valor de la
métrica en el que la carga de trabajo deja de completar (la query falla o se cae
la conexión). El **throughput** medido es **aplicativo**: bytes de payload MySQL
transferidos / duración de la ventana, medidos capturando el tráfico 3306 mientras
se corre una carga de trabajo fija (una query `SELECT` con JOIN sobre `posts` y
`likes`, repetida 5 veces). Timeout por query: 10 s.

**Herramienta:** `metricas/barrido.py` (aplica netem, corre la carga, mide,
exporta CSV) y `metricas/graficar.py` (genera el PNG).

### 8.1 Métrica 1 — Latencia (delay)
**Comando:**
```
python3 /scripts/metricas/barrido.py --metrica delay --valores 0 200 800 1600 2400 3000 4000 5000
```
**Datos reales** (`scapy/scripts/metricas/resultados_delay.csv`):

| delay (ms) | throughput (bps) | latencia_query (ms) | estado |
|-----------:|-----------------:|--------------------:|--------|
| 0    | 615.796 | 15    | ok |
| 200  | 11.614  | 814   | ok |
| 800  | 2.940   | 3.214 | ok |
| 1600 | 1.639   | 6.414 | ok |
| 2400 | 1.101   | 9.614 | ok |
| **3000** | 917 | 10.000 | **fallo** |
| 4000 | 392     | 10.000 | fallo |
| 5000 | 230     | 10.000 | fallo |

**COTA DE DESEMPEÑO: +3000 ms.** Hasta 2400 ms la query completa (en 9,6 s); a
partir de 3000 ms supera el timeout de 10 s (`latencia_query` clavada en 10.000)
y **falla**.

**Fundamentación:** la relación delay↔throughput es **inversamente proporcional**
(a más delay, menos throughput). La cota (~3 s de delay) es relativamente baja
porque **cada query MySQL involucra ~4 round-trips** (handshake + autenticación +
query + resultado); cada round-trip paga el delay, así que a 2400 ms el tiempo
total ya es 9,6 s, y a 3000 ms supera el timeout. Este es un punto de análisis
importante: la cota del *servicio* es mucho menor que el timeout configurado por
efecto de la multiplicidad de round-trips del protocolo.

**Gráfico:** `scapy/scripts/metricas/delay_vs_throughput.png` — eje X = delay
(ms), eje Y = throughput (bps), línea roja punteada marcando la cota en +3000 ms.
Muestra una caída abrupta del throughput ya con los primeros 200 ms de delay
(curva de tipo 1/x).

### 8.2 Métrica 2 — Pérdida de paquetes (loss)
**Comando:**
```
python3 /scripts/metricas/barrido.py --metrica loss --valores 0 1 5 10 20 40 60
```
**Datos reales** (`scapy/scripts/metricas/resultados_loss.csv`):

| loss (%) | throughput (bps) | latencia_query (ms) | estado |
|---------:|-----------------:|--------------------:|--------|
| 0  | 647.887 | 15    | ok |
| 1  | 708.567 | 13    | ok |
| 5  | 99.078  | 98    | ok |
| 10 | 31.926  | 298   | ok |
| 20 | 11.375  | 839   | ok |
| 40 | 6.277   | 1.570 | ok |
| **60** | 1.553 | 4.977 | **degradado** |

**COTA DE DESEMPEÑO: +60 % (rango difuso ~40–60 %).** Hasta 40 % todas las queries
completan; a 60 % algunas fallan (`degradado` = no todas las 5 repeticiones
completaron).

**Fundamentación:** el impacto de la pérdida es **brutal y no lineal**: con solo
**5 %** de pérdida el throughput se desploma de ~650k a ~99k bps (−85 %). La causa
son las **retransmisiones TCP con backoff exponencial**: cada paquete perdido
obliga a TCP a esperar el RTO (Retransmission TimeOut) antes de reenviar, y ese
tiempo muerto destruye el throughput mucho antes de que la conexión caiga del
todo. A diferencia del delay (cota nítida y determinista), la cota de `loss` es un
**rango difuso** porque la pérdida es **probabilística** (netem descarta paquetes
al azar): repitiendo el barrido, la cota puede caer en 40 % u 80 % según la
suerte. El estado `degradado` (fallan algunas, no todas) refleja precisamente esa
naturaleza estocástica.

**Gráfico:** `scapy/scripts/metricas/loss_vs_throughput.png` — eje X = loss (%),
eje Y = throughput (bps), línea roja punteada en la cota +60 %. Muestra la caída
abrupta ya con 5 % de pérdida.

### 8.3 Comparación de las dos métricas (para la discusión del informe)
| Aspecto | Delay (tiempo) | Loss (confiabilidad) |
|---------|----------------|----------------------|
| Qué mide | Retardo de la red | Fiabilidad del enlace |
| Naturaleza | Determinista | Estocástica (probabilística) |
| Cota | Nítida: +3000 ms | Difusa: ~40–60 % |
| Mecanismo de degradación | Multiplicidad de round-trips del protocolo | Retransmisiones TCP + RTO |
| Forma de la curva | Caída 1/x, throughput→0 suave | Caída abrupta temprana (ya en 5 %) |

---

## 9. Inventario de archivos entregados (todo en el repositorio)

**Scripts (`scapy/scripts/`):**
- `sniffer.py`, `sniff_test.py`, `mitm_nfqueue.py`, `fuzzing.py`, `arp_spoof.py`.
- `metricas/barrido.py`, `metricas/graficar.py`.

**Evidencia generada:**
- `captura_mysql.pcap` — captura de tráfico MySQL (abrible en Wireshark).
- `log_captura.txt` — log parseado de la captura.
- `log_mitm.txt` — log de las 3 modificaciones.
- `log_fuzzing.txt` — log de las 2 inyecciones de fuzzing (con error packets).
- `metricas/resultados_delay.csv`, `metricas/resultados_loss.csv` — datos crudos.
- `metricas/delay_vs_throughput.png`, `metricas/loss_vs_throughput.png` — gráficos.

**Infraestructura (raíz del repo):**
- `docker-compose.yml` — 3 servicios (servidor MariaDB, cliente CloudBeaver, scapy).
- `scapy/Dockerfile`, `cliente/Dockerfile`, `servidor/Dockerfile`.
- `db/schema_taller_redes.sql` — esquema de la base `taller_redes`.

---

## 10. Estructura sugerida del informe LaTeX

1. **Portada** — título, integrantes, asignatura, fecha, link del video y repo.
2. **Introducción** — objetivo de la tarea, servicio y protocolo elegidos (§1).
3. **Marco teórico** — protocolo MySQL y su header de 5 bytes (§3); qué es NFQUEUE,
   netem, fuzzing.
4. **Arquitectura del entorno** — topología, Estrategia A, contenedores (§2), con
   diagrama.
5. **Metodología y herramientas** — los scripts desarrollados (§4).
6. **Actividad 1: Interceptación** (§5) — con extracto del log y mención al pcap.
7. **Actividad 2: Modificaciones de campos** (§6) — las 3, con esperado/observado/
   hipótesis y screenshots de CloudBeaver.
8. **Actividad 3: Fuzzing** (§7) — las 2 inyecciones, con los error packets.
9. **Actividad 4: Métricas y cotas** (§8) — tablas, fundamentaciones y los 2
   gráficos como figuras.
10. **Estrategia B evaluada y descartada** (§2, subsección ARP spoofing).
11. **Conclusiones** — qué reveló cada modificación/inyección sobre la robustez
    del servicio; comparación de las dos métricas (§8.3); relación entre las
    cotas y el diseño del protocolo (round-trips).
12. **Anexos** — inventario de archivos (§9), comandos de reproducción.

### Elementos que el agente LaTeX debe generar como figuras/tablas
- Diagrama de topología (§2). Puede hacerse con TikZ.
- Diagrama del header MySQL de 5 bytes (§3). TikZ o tabla.
- Tabla de decodificación del ERROR packet (§3).
- Tablas resumen de modificaciones (§6.4) y fuzzing (§7.3).
- Figuras: `delay_vs_throughput.png` y `loss_vs_throughput.png` (§8).
- Tablas de datos de delay (§8.1) y loss (§8.2).
- Tabla comparativa de métricas (§8.3).
- Bloques `verbatim`/`lstlisting` para los extractos de logs y hexdumps.

### Datos a completar por los integrantes antes de compilar
- Nombres de los integrantes (§0).
- URL del repositorio y del video (§0).
- Screenshots de CloudBeaver para las Modificaciones A (error Unknown database)
  y B (spinner "Loading…"), y para la inyección 1 si se desea.
- Resultado observado de la Modificación A en CloudBeaver (§6.1, §6.4) —
  confirmar si mostró `ERROR 1049 Unknown database`.
