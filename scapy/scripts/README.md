# Scripts de Scapy — Tarea 3 (intercepción, fuzzing y métricas MySQL)

Este directorio se monta en `/scripts` dentro del contenedor `scapy_mitm`.
Edítalos desde el host; se reflejan al instante (no hay que reconstruir), salvo
cambios en el `Dockerfile` (`docker compose up -d --build`).

Estrategia activa: **A — NFQUEUE + namespace compartido** (`network_mode:
service:cliente`). La Estrategia B (ARP spoofing) queda documentada pero **no
ejecutada** — ver `arp_spoof.py` y el spec §3.

## Archivos

| Script | Rol | Spec |
|---|---|---|
| `sniffer.py` | Captura definitiva: pcap + log + parseo/clasificación MySQL. Exporta `parsear_mysql_header()`. | §4 |
| `sniff_test.py` | Prueba de humo (solo observa). | §1 |
| `mitm_nfqueue.py` | 3 modificaciones de campos (comando / largo / sequence_id). | §2 |
| `fuzzing.py` | 2 inyecciones vía fuzzing (comando / largo). | §6 |
| `metricas/barrido.py` | Barrido de delay/loss con netem + throughput aplicativo → CSV. | §7 |
| `metricas/graficar.py` | Gráfico métrica vs throughput con la cota marcada. | §7.6 |
| `arp_spoof.py` | Estrategia B — diseño explorado, NO ejecutado. | §3 |

## 1. Captura (evidencia base)

```bash
docker exec -it scapy_mitm python3 /scripts/sniffer.py --duracion 60
# mientras corre, ejecutá queries desde CloudBeaver (http://localhost:8978)
```
Genera `captura_mysql.pcap` (abrir en Wireshark) y `log_captura.txt` (para citar
en el informe). Al cortar imprime un resumen por tipo de mensaje.

## 2. Modificación de campos — Estrategia A (NFQUEUE)

Redirigí el tráfico MySQL a la cola (comparte la netns del cliente):
```bash
docker exec -it scapy_mitm bash
iptables -A OUTPUT -p tcp --dport 3306 -j NFQUEUE --queue-num 1
iptables -A INPUT  -p tcp --sport 3306 -j NFQUEUE --queue-num 1
```
Editá la constante `MODO` en `mitm_nfqueue.py` (`comando` | `largo` |
`sequence_id`, una por vez) y lanzá:
```bash
python3 /scripts/mitm_nfqueue.py
```
Generá una query desde CloudBeaver y observá el efecto. Log en `log_mitm.txt`.
Limpiar reglas: `iptables -F`.

## 3. Fuzzing (2 inyecciones)

Con las mismas reglas iptables de arriba:
```bash
python3 /scripts/fuzzing.py --modo comando   # inyección 1: comando inexistente
python3 /scripts/fuzzing.py --modo largo      # inyección 2: largo declarado 16MB
```
Reescribe el payload de un `COM_QUERY` real (hereda seq/ack de la conexión viva).
Log en `log_fuzzing.txt`, incluye el error packet del servidor si lo hay.

## 4. Métricas, cotas y gráficos

No requiere reglas iptables (usa `tc netem`, no NFQUEUE):
```bash
# barridos (cada uno deja un CSV en metricas/)
python3 /scripts/metricas/barrido.py --metrica delay --valores 0 50 100 200 400 800 1600
python3 /scripts/metricas/barrido.py --metrica loss  --valores 0 1 5 10 20 40 60

# gráficos métrica vs throughput (marcan la cota)
python3 /scripts/metricas/graficar.py --csv /scripts/metricas/resultados_delay.csv
python3 /scripts/metricas/graficar.py --csv /scripts/metricas/resultados_loss.csv
```
La **cota** es el primer valor con estado != `ok`. Entregables:
`resultados_*.csv` y `*_vs_throughput.png`.

## Verificar la captura manualmente

```
tcpdump -i eth0 -n port 3306 -A          # ver payload MySQL en claro
tshark  -i eth0 -f 'tcp port 3306' -x    # hex + protocolo
```

## Estrategia B — ARP spoofing (NO usada, solo referencia)

`arp_spoof.py` documenta la alternativa evaluada. Para ejecutarla habría que
mover `scapy` de `network_mode: service:cliente` a `networks: db_network` en el
`docker-compose.yml` (ver spec §3). No se graba demo en el video.
