# Spec de correcciones — Tarea 3 (Taller de Redes)

> **Alcance de este documento.** Las secciones 1–5 cubren *interceptar* y
> *modificar* tráfico (parte 1 del enunciado). Las secciones 6 y 7 cubren las
> otras dos partes que la tarea exige y que la versión previa del spec no
> abordaba: **fuzzing** (2 inyecciones) y **métricas de red + cotas de
> desempeño + gráficos** (2 métricas ≠ throughput/goodput). El mapa completo
> requisito→entregable está en la sección 8.

---

## 1. `sniff_test.py`

### Error
No se especifica `iface` en `sniff()`. El contenedor `scapy_mitm` comparte namespace
con `cliente` (`network_mode: service:cliente`), por lo que normalmente tiene solo
`eth0` + `lo`. Scapy auto-detecta la interfaz "default", pero en contenedores esa
detección a veces resuelve `lo` en vez de `eth0`, dependiendo de la tabla de rutas
que Docker arma al momento del build. Cuando eso pasa, el script corre sin errores
pero **no captura nada**, y el síntoma (silencio total) es indistinguible de "no hay
tráfico" — lleva a perder tiempo debuggeando la red cuando el problema es una línea.

### Solución
```python
IFACE = "eth0"

sniff(filter="tcp port 3306", iface=IFACE, prn=procesar, store=0, timeout=DURACION)
```
Agregar además, antes del `sniff()`, una verificación explícita:
```python
from scapy.all import get_if_list
if IFACE not in get_if_list():
    raise RuntimeError(f"Interfaz {IFACE} no existe. Interfaces disponibles: {get_if_list()}")
```

### Por qué arregla el problema
Fijar `iface` elimina la ambigüedad de auto-detección: le decís a Scapy exactamente
dónde escuchar, en vez de depender de heurísticas de "cuál es la ruta por defecto"
que en un contenedor con namespace compartido pueden no coincidir con lo que vos
esperás. El chequeo con `get_if_list()` convierte un fallo silencioso (0 paquetes,
sin explicación) en un error explícito que te dice qué interfaces existen realmente
dentro del contenedor.

---

## 2. `mitm_nfqueue.py`

### Error 1 — Parsing de payload como texto libre en vez de header MySQL estructurado
El script busca `"SELECT"`/`"INSERT"` como substring dentro de `Raw`, sin parsear los
5 bytes de header MySQL (3 bytes largo + 1 byte sequence_id + 1 byte comando). Para
las 3 modificaciones que pide la tarea (comando, largo, sequence_id) necesitás
direccionar esos bytes por posición exacta, no por búsqueda de texto — buscar texto
no te da forma de tocar el sequence_id o el largo declarado, que no son texto.

### Solución 1
```python
def parsear_mysql_header(payload: bytes):
    if len(payload) < 5:
        return None
    largo = int.from_bytes(payload[0:3], "little")
    seq_id = payload[3]
    comando = payload[4]
    resto = payload[5:]
    return largo, seq_id, comando, resto
```
Reemplazar la búsqueda de texto por este parser, y condicionar cada modificación al
campo correspondiente (ver bloque de "Modificaciones" más abajo).

### Por qué arregla el problema
El protocolo MySQL define esos 5 bytes como header fijo antes de cualquier query en
texto plano. Parsear por posición te da acceso determinístico a cada campo que la
tarea pide modificar, en vez de depender de que la query "contenga" cierta palabra
(lo cual además falla para queries que no son SELECT/INSERT, como los propios
paquetes de handshake).

### Error 2 — Solo una modificación activa a la vez sin trazabilidad de cuál se ejecutó
El bloque de ejemplo comentado no deja registro de qué modificación se aplicó a qué
paquete, lo cual es un problema para el informe: necesitás poder correlacionar cada
captura de video/hexdump con el campo que estabas modificando en ese momento.

### Solución 2
Usar una variable de configuración al tope del archivo que seleccione el modo activo,
y loguear explícitamente antes de modificar:
```python
MODO = "comando"  # "comando" | "largo" | "sequence_id" | None (solo observar)

def procesar(pkt):
    ip = IP(pkt.get_payload())
    if ip.haslayer(Raw):
        payload = bytes(ip[Raw].load)
        parsed = parsear_mysql_header(payload)
        if parsed:
            largo, seq_id, comando, resto = parsed
            nuevo_payload = None

            if MODO == "comando" and comando == 0x03:
                nuevo_payload = payload[:4] + bytes([0x02]) + resto
                print(f"[MOD comando] 0x03 -> 0x02 | seq={seq_id}")

            elif MODO == "largo" and comando == 0x03:
                nuevo_largo = (largo + 50).to_bytes(3, "little")
                nuevo_payload = nuevo_largo + payload[3:]
                print(f"[MOD largo] {largo} -> {largo+50} | seq={seq_id}")

            elif MODO == "sequence_id" and comando == 0x03:
                nuevo_seq = bytes([(seq_id + 5) % 256])
                nuevo_payload = payload[:3] + nuevo_seq + payload[4:]
                print(f"[MOD sequence_id] {seq_id} -> {(seq_id+5)%256}")

            if nuevo_payload is not None:
                ip[Raw].load = nuevo_payload
                del ip[IP].len, ip[IP].chksum, ip[TCP].chksum
                pkt.set_payload(bytes(ip))
                pkt.accept()
                return
    pkt.accept()
```

### Por qué arregla el problema
Centralizar el modo en una sola variable te obliga a correr una modificación por
vez (requisito implícito de la tarea: fundamentar cada una por separado), y el
`print` de cada modificación te da timestamps y valores exactos para citar en el
informe sin tener que reconstruirlos de memoria después de grabar el video.

### Error 3 — No se documenta el efecto de TCP por debajo de la modificación
`del ip[IP].len, ip[IP].chksum, ip[TCP].chksum` recalcula correctamente los
checksums de IP y TCP, pero **no toca los números de secuencia TCP** (`seq`/`ack`).
Si el campo modificado (ej. largo declarado) hace que el largo real de bytes no
coincida con el declarado, el servidor puede quedarse esperando bytes adicionales
— la conexión no cae por checksum inválido, cae por timeout de aplicación con el
stream TCP subyacente todavía "sano".

### Solución 3
No es un bug de código sino una nota que debe ir en el propio script (y en el
informe), para no confundir un timeout esperado con un fallo del script:
```python
# NOTA: modificar el largo declarado sin ajustar seq/ack de TCP puede producir
# un timeout de aplicación (MySQL esperando más bytes) en vez de un error de
# protocolo inmediato. Es el comportamiento esperado, no un bug del script.
```

### Por qué arregla el problema
Evita que interpretes un timeout como "la modificación no funcionó" cuando en
realidad es la consecuencia correcta de desincronizar el largo declarado — te da
la hipótesis lista para la sección de fundamentación de la tarea.

---

## 3. `arp_spoof.py`

### Decisión: DESCARTADO — no se implementa

Se evaluó la Estrategia B (Scapy como tercer nodo independiente en `db_network`,
envenenando las cachés ARP de servidor y cliente para insertarse en medio) y se
decidió **no usarla**. Motivos:

- El enunciado pide interceptar/modificar tráfico y encontrar cotas de
  desempeño — no pide comparar dos técnicas de MITM distintas. La Estrategia A
  (NFQUEUE + namespace compartido) ya cubre completamente los requisitos de
  fuzzing y modificación de campos.
- Cambiar a Estrategia B implica reconstruir la topología de red
  (`network_mode` → `networks`), revalidar sniff y NFQUEUE en la nueva
  configuración, y sincronizar el timing del envenenamiento con las queries en
  CloudBeaver — tiempo que compite directo con las 3 modificaciones de campos,
  que es donde está el peso real de la tarea.
- Riesgo de estado inconsistente cerca de la entrega: una restauración de ARP
  fallida a mitad de una grabación puede colgar la conexión cliente-servidor
  justo cuando se necesita todo funcionando fluido para el video.

### Error de diseño identificado (documentar en el informe, no corregir en código)
El script tal como está escrito asume que `scapy_mitm` tiene IP/MAC propia y
distinta de cliente y servidor. Pero el `docker-compose.yml` actual tiene activa
`network_mode: "service:cliente"`, es decir `scapy_mitm` **es** la misma pila de
red que `cloudbeaver_client` — no hay "medio" en el que insertarse, un
contenedor no puede ARP-spoofearse respecto de sí mismo. Este es justamente el
punto conceptual que conviene explicar en el informe para demostrar que la
Estrategia B fue evaluada y entendida, no solo omitida.

### Tratamiento en los entregables
- **Informe**: sección corta (media página) explicando la Estrategia B como
  alternativa evaluada, el conflicto estructural con `network_mode:
  service:cliente`, y la justificación de por qué se optó por Estrategia A.
- **Repositorio**: `arp_spoof.py` se sube igual, comentado al inicio como
  "diseño explorado, no ejecutado en la entrega final" para dejar constancia
  del trabajo de análisis sin implicar que fue validado en video.
- **Video**: no se graba demo de este script.
- Si sobra tiempo después de cerrar fuzzing + NFQUEUE + métricas + informe, se
  puede retomar como extra, pero no es parte del camino crítico.

---

## 4. Requisitos y spec del script `sniffer.py` (entregable consolidado)

Este archivo es el que debería quedar en el repo como evidencia central del punto
"Interceptar con Scapy el tráfico generado entre sus aplicaciones" del enunciado.
A diferencia de `sniff_test.py` (que es solo una prueba de humo), `sniffer.py` debe
ser el script de captura definitivo, reutilizable como evidencia para el informe y
el video.

### Debe contener

1. **Captura filtrada por puerto MySQL** (`tcp port 3306`), con `iface` fijo y
   verificado contra `get_if_list()` (mismo fix que en `sniff_test.py`).

2. **Parseo de header MySQL por posición** (reutilizando `parsear_mysql_header()`),
   no solo un resumen genérico de Scapy — el informe necesita mostrar que ustedes
   entienden la estructura del protocolo, no solo que "ven paquetes".

3. **Clasificación de paquetes por tipo de mensaje MySQL**, al menos:
   - Handshake inicial (server greeting)
   - `COM_QUERY` (0x03)
   - Resultset / respuesta del servidor
   - Error packets (`0xFF` como primer byte del payload de respuesta)

4. **Persistencia de evidencia**, no solo `print()` en pantalla:
   ```python
   from scapy.utils import wrpcap
   capturados = []

   def procesar(pkt):
       capturados.append(pkt)
       ...

   # al final de la captura:
   wrpcap("/scripts/captura_mysql.pcap", capturados)
   ```
   El `.pcap` generado es lo que suben al repositorio como "archivos que puedan
   utilizar en la realización de la tarea" (requisito explícito del enunciado), y
   permite abrir la captura en Wireshark para el informe sin tener que re-ejecutar
   nada en vivo.

5. **Log estructurado a archivo de texto**, en paralelo al pcap, con una línea por
   paquete relevante en formato fácil de citar en el informe:
   ```python
   with open("/scripts/log_captura.txt", "a") as f:
       f.write(f"{timestamp} | seq={seq_id} | cmd=0x{comando:02x} | largo={largo} | query={resto[:60]!r}\n")
   ```

6. **Parámetros configurables por CLI** (usando `argparse`), en vez de constantes
   hardcodeadas, para poder reutilizar el mismo script en fuzzing/NFQUEUE sin
   duplicar código:
   ```python
   parser.add_argument("--iface", default="eth0")
   parser.add_argument("--duracion", type=int, default=60)
   parser.add_argument("--output", default="/scripts/captura_mysql.pcap")
   ```

### Cómo debe funcionar (flujo de ejecución)

1. Se ejecuta manualmente antes de correr una query en CloudBeaver:
   ```bash
   docker exec -it scapy_mitm python3 /scripts/sniffer.py --duracion 60
   ```
2. Mientras está corriendo, se dispara tráfico real desde CloudBeaver (una o varias
   queries).
3. Al cortar (por timeout o `Ctrl+C`), el script:
   - Escribe el `.pcap` completo a disco.
   - Escribe el log de texto con el resumen parseado de cada paquete MySQL.
   - Imprime un resumen final en consola (cantidad de paquetes por tipo:
     handshake / query / resultset / error).
4. Los dos archivos de salida (`captura_mysql.pcap`, `log_captura.txt`) son la
   evidencia base que se reutiliza en:
   - El informe (hexdumps, capturas de Wireshark abriendo el pcap).
   - El video (mostrar el log en vivo mientras se ejecuta la query).
   - Los otros scripts (`fuzzing.py`, `mitm_nfqueue.py`), que pueden usar el mismo
     `parsear_mysql_header()` importándolo desde `sniffer.py` en vez de
     duplicarlo, para mantener un único punto de verdad sobre el formato del
     protocolo.

---

## 5. Próximo paso acordado

1. Implementar `sniffer.py` completo según la spec de la sección 4, con
   `parsear_mysql_header()` como función exportable.
2. Refactorizar `mitm_nfqueue.py` para importar `parsear_mysql_header()` desde
   `sniffer.py` en vez de mantener una copia propia del parser, evitando que
   los dos scripts queden desincronizados si el formato de parseo cambia.
3. Implementar `fuzzing.py` según la sección 6 (2 inyecciones de fuzzing).
4. Implementar el pipeline de métricas de la sección 7 (`netem` + medición de
   throughput + barrido de cotas + gráficos).
5. `arp_spoof.py` queda tal como está, sin más trabajo de código — solo se le
   agrega el comentario de "diseño explorado, no ejecutado" y se documenta en
   el informe según la sección 3.

---

## 6. `fuzzing.py` — dos inyecciones de tráfico vía fuzzing

El enunciado pide explícitamente **"dos inyecciones de tráfico haciendo uso de
técnicas de fuzzing"**. Esto es distinto de las 3 modificaciones de la sección 2:
ahí interceptás un paquete real y le cambiás un campo puntual; acá **generás e
inyectás paquetes nuevos** con contenido (semi)aleatorio o malformado para ver
cómo reacciona el servicio ante entrada no prevista.

> **Aclaración conceptual (va también en el informe).** Fuzzing = alimentar al
> objetivo con datos inválidos/inesperados/aleatorios y observar fallos
> (crash, error, cuelgue, comportamiento anómalo). Las 3 modificaciones de la
> §2 son *tampering* de campos válidos; las 2 de acá son *inyección de basura*.
> Son requisitos separados del enunciado y no se pueden cumplir con el mismo
> paquete.

### Requisito de la tarea para cada inyección
- Se inyecta tráfico y se observa/registra la repercusión sobre el servicio.
- Queda evidencia (pcap + log + captura de video) del antes/después.

### Inyección 1 — Fuzzing del campo `comando` del header MySQL
Inyectar paquetes MySQL bien formados en los primeros 4 bytes (largo + seq_id
coherentes) pero con el **byte de comando** tomando valores aleatorios o fuera
del rango válido (`0x00`–`0x1f` son comandos definidos; probar `0x20`–`0xff`,
inexistentes).

```python
import random
# sobre una conexión TCP ya establecida al 3306 (ver nota de estado TCP abajo)
for _ in range(20):
    comando = random.randint(0x20, 0xff)   # comandos inexistentes
    cuerpo  = bytes([comando]) + random.randbytes(random.randint(0, 40))
    largo   = len(cuerpo).to_bytes(3, "little")
    seq_id  = bytes([0x00])
    payload = largo + seq_id + cuerpo
    # inyectar payload dentro del stream (ver estrategia de inyección abajo)
```

**Comportamiento esperado a fundamentar:** MariaDB debería responder con un
*error packet* (`0xFF` + código de error, típicamente 1047 "Unknown command")
y, según el caso, cerrar la conexión. Documentar cuál código devuelve.

### Inyección 2 — Fuzzing con `scapy.fuzz()` sobre el payload / largos absurdos
Aprovechar el fuzzing nativo de Scapy y/o declarar un **largo** enorme en el
header con un cuerpo corto (mentir sobre cuántos bytes vienen), y viceversa.

```python
from scapy.all import fuzz, IP, TCP, Raw
# opción A: payload MySQL con largo declarado desacoplado del real
cuerpo  = random.randbytes(10)
largo   = (0xFFFFFF).to_bytes(3, "little")   # dice "16MB" y manda 10 bytes
payload = largo + b"\x00" + cuerpo
# opción B: fuzz() de Scapy sobre capas para basura estructurada
pkt = IP(dst=SERVIDOR_IP)/TCP(dport=3306, flags="PA")/fuzz(Raw())
```

**Comportamiento esperado a fundamentar:** con el largo inflado, el servidor
queda esperando bytes que no llegan → **timeout de aplicación** (mismo
mecanismo que la nota TCP de la §2, error 3). Con `fuzz()` puro, lo más probable
es un error de protocolo o el descarte del paquete. En ambos casos **formular la
hipótesis** si el comportamiento observado no coincide con el esperado
(requisito explícito del enunciado).

### Estrategia de inyección (decisión de implementación)
Hay dos formas de inyectar y conviene elegir una y justificarla en el informe:

- **(Recomendada) Reescritura vía NFQUEUE**, reutilizando el mismo pipeline de
  `mitm_nfqueue.py`: se espera un paquete `COM_QUERY` real del cliente y se
  **reemplaza su payload** por el payload fuzzeado antes de `pkt.accept()`. Esto
  hereda automáticamente los seq/ack correctos de la conexión TCP viva de
  CloudBeaver — evitás tener que construir el handshake MySQL y el three-way
  handshake TCP a mano. Es la opción de menor riesgo para el video.
- **(Alternativa, más costosa) Inyección cruda con `send()`/`sr()`** abriendo
  vos mismo el socket TCP + handshake MySQL. Más "puro" como fuzzing pero exige
  manejar seq/ack, autenticación y estado — alto riesgo de que se caiga la demo.
  Si se usa, documentar por qué.

> **Nota de estado TCP (misma familia que §2 error 3).** Cualquier inyección que
> cambie el largo del stream sin ajustar seq/ack rompe la sincronización TCP. Por
> eso la vía NFQUEUE (reemplazo in-place sobre un paquete ya en vuelo) es la que
> menos estado rompe: dejá que el kernel del cliente maneje el TCP.

### Salidas esperadas de `fuzzing.py`
- `--modo {comando,largo}` para elegir la inyección (una por vez, igual criterio
  que `MODO` en §2, para trazabilidad en el informe).
- `print`/log de cada paquete inyectado (valor fuzzeado + timestamp).
- Guardar la respuesta del servidor (error packet / cierre / timeout) al mismo
  `log_captura.txt` o a uno propio `log_fuzzing.txt`.

---

## 7. Métricas de red, cotas de desempeño y gráficos

El enunciado pide **2 métricas distintas de throughput y goodput, que midan dos
aspectos distintos de la red**, y por cada una: (a) la **cota de desempeño**
(valor/rango donde el servicio se degrada) y (b) un **gráfico métrica vs
throughput**. La versión previa del spec no cubría nada de esto y es
aproximadamente la mitad del peso de la tarea.

### 7.1 Elección de las dos métricas
- **Métrica 1 — Latencia / delay (retardo de red).** Mide el *tiempo* de la red.
- **Métrica 2 — Packet loss (pérdida de paquetes).** Mide la *confiabilidad* del
  enlace.

Son dos aspectos distintos (tiempo vs pérdida), como exige el enunciado. Se
inyectan con `tc` + `netem` de `iproute2` (ya instalado en el `Dockerfile` de
scapy; requiere `NET_ADMIN`, ya presente en `cap_add`). **Decisión tomada:** la
métrica 2 es `loss` (no `jitter`); pérdida y latencia son las dos familias
elegidas y quedan fijas para todo el pipeline.

> **Dónde aplicar `netem`.** Como `scapy_mitm` comparte netns con el cliente
> (`network_mode: service:cliente`), el `tc` se aplica sobre la `eth0` de esa
> netns compartida y afecta el tráfico cliente↔servidor. Confirmar la interfaz
> con `ip link` dentro del contenedor antes de correr el barrido.

### 7.2 Inyección de cada métrica (comandos base)

```bash
# Latencia: agrega 100ms de delay a todo el tráfico saliente de eth0
tc qdisc add dev eth0 root netem delay 100ms
tc qdisc change dev eth0 root netem delay 200ms   # subir el valor en el barrido
tc qdisc del dev eth0 root                          # limpiar al terminar

# Pérdida: descarta el 10% de los paquetes
tc qdisc add dev eth0 root netem loss 10%
tc qdisc change dev eth0 root netem loss 25%
tc qdisc del dev eth0 root
```

### 7.3 Definición de la cota de desempeño
Para cada métrica, hacer un **barrido creciente** del valor y en cada punto
ejecutar una carga de trabajo repetible desde el cliente (ej. una query pesada o
un `SELECT` que traiga N filas de `schema_taller_redes.sql`, o un `mysqlslap` /
bucle de queries). La **cota** es el valor a partir del cual el servicio se
degrada de forma clara: la query falla, se cae la conexión, CloudBeaver da
timeout, o el throughput cae por debajo de un umbral acordado.

- Delay: barrer p.ej. `0, 50, 100, 200, 400, 800, 1600 ms` hasta que
  CloudBeaver/driver corte la conexión (típico `connect_timeout` / `net_read_timeout`).
- Loss: barrer `0, 1, 5, 10, 20, 40, 60 %` hasta que la conexión se vuelva
  inutilizable (retransmisiones TCP saturan y la query nunca completa).

Registrar el resultado como en el ejemplo del enunciado: *"hasta X el servicio
funciona; sobre X se degrada/cae → +X es la cota"*.

### 7.4 Medición del throughput durante el barrido
**Decisión tomada: throughput aplicativo** (no iperf3). Se mide el throughput
real del *servicio* MySQL, que es lo que la tarea evalúa, y reutiliza el
`sniffer.py` que ya vamos a tener en vez de introducir un enlace sintético.

Por cada punto del barrido:
1. Ejecutar una carga de trabajo fija (una query que traiga N filas de
   `schema_taller_redes.sql`, repetida M veces) desde el cliente.
2. Capturar el tráfico 3306 de esa ventana con `sniffer.py` a un `.pcap`.
3. Throughput = (suma de bytes de payload MySQL en la ventana) / (duración de la
   ventana). Se deriva del `.pcap` sumando los `len(Raw.load)`, o con
   `tshark -q -z io,stat,0,"tcp.port==3306"` sobre el mismo pcap.

Ventaja adicional: el mismo `parsear_mysql_header()` permite separar, si se
quiere, bytes de query vs bytes de resultset para afinar la medición.

### 7.5 Automatización: `metricas/barrido.py` (o `.sh`)
Script que, para una métrica y una lista de valores:
1. Aplica el valor con `tc ... netem`.
2. Lanza la carga de trabajo (query repetida) desde/hacia el servidor.
3. Mide el throughput resultante (§7.4).
4. Registra `(valor_metrica, throughput, ok/fallo)` en un CSV.
5. Limpia el `qdisc` y pasa al siguiente valor.

```
# formato de salida sugerido: metricas/resultados_<metrica>.csv
metrica,valor,throughput_bps,latencia_query_ms,estado
delay,0,,,ok
delay,200,...,...,ok
delay,1600,...,...,timeout   <-- cota
```

### 7.6 Gráficos métrica vs throughput
Un gráfico por métrica (2 en total), eje X = valor de la métrica, eje Y =
throughput, marcando la cota de desempeño con una línea vertical/anotación.

```python
# metricas/graficar.py  — matplotlib, lee el CSV del barrido
import csv, matplotlib.pyplot as plt
# ... leer resultados_delay.csv y resultados_loss.csv
plt.plot(valores, throughputs, marker="o")
plt.axvline(cota, color="red", linestyle="--", label=f"cota = {cota}")
plt.xlabel("delay (ms)"); plt.ylabel("throughput (bps)")
plt.savefig("metricas/delay_vs_throughput.png")
```

> **Dependencia nueva.** `matplotlib` no está en el `Dockerfile` de scapy.
> Agregarlo al `pip3 install` (`scapy NetfilterQueue matplotlib`) o generar los
> PNG en el host desde los CSV. Recomendado agregarlo al Dockerfile para que todo
> el pipeline corra dentro del contenedor y quede reproducible.

### 7.7 Entregables de esta sección
- `metricas/resultados_delay.csv`, `metricas/resultados_loss.csv` (datos crudos).
- `metricas/delay_vs_throughput.png`, `metricas/loss_vs_throughput.png` (gráficos).
- En el informe: las dos cotas con su fundamentación, y los dos gráficos.
- En el video: mostrar el barrido corriendo y cómo cae el servicio al pasar la cota.

---

## 8. Mapa requisito del enunciado → entregable

| Requisito de la Tarea 3 | Cubierto por | Estado |
|---|---|---|
| Interceptar tráfico con Scapy | `sniffer.py` (§4) + `.pcap`/log | por implementar |
| 2 inyecciones vía fuzzing | `fuzzing.py` (§6) | por implementar |
| 3 modificaciones de campos del protocolo | `mitm_nfqueue.py` (§2) | por implementar |
| Fundamentar c/modificación (esperado + hipótesis) | informe, apoyado en §2/§6 | por redactar |
| 2 métricas ≠ throughput/goodput | delay + loss vía `netem` (§7) | por implementar |
| Cota de desempeño por métrica | barrido §7.3 | por implementar |
| Gráfico métrica vs throughput (×2) | `graficar.py` (§7.6) | por implementar |
| Estrategia B evaluada y descartada | `arp_spoof.py` + informe (§3) | documentar |
| Video 6–8 min + archivos al repo + informe Canvas | entregable final | pendiente |