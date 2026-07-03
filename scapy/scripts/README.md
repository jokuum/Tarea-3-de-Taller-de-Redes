# Scripts de Scapy — Tarea 3 (intercepción MySQL)

Este directorio se monta en `/scripts` dentro del contenedor `scapy_mitm`.
Edítalos desde el host; se reflejan al instante (no hay que reconstruir).

## Estrategia A — NFQUEUE (recomendada para modificar tráfico)

1. En `docker-compose.yml`, en el servicio `scapy`, comenta el bloque
   `networks:` y descomenta `network_mode: "service:cliente"`.
2. Reconstruye/levanta:  `docker compose up -d --build`
3. Entra al contenedor:  `docker exec -it scapy_mitm bash`
4. Redirige el tráfico MySQL a la cola NFQUEUE (comparte la netns del cliente):
   ```
   iptables -A OUTPUT -p tcp --dport 3306 -j NFQUEUE --queue-num 1
   iptables -A INPUT  -p tcp --sport 3306 -j NFQUEUE --queue-num 1
   ```
5. Lanza el interceptor:  `python3 /scripts/mitm_nfqueue.py`
6. Genera tráfico desde CloudBeaver (http://localhost:8978) ejecutando queries.

Para limpiar las reglas:  `iptables -F`

## Estrategia B — ARP spoofing (MITM como tercero en db_network)

1. En `docker-compose.yml` deja el bloque `networks:` activo (por defecto).
2. `docker exec -it scapy_mitm bash`
3. Averigua las IPs:  `getent hosts mariadb_server cloudbeaver_client`
4. `python3 /scripts/arp_spoof.py`  (envenena ambas cachés ARP)
5. Con `ip_forward=1` + regla FORWARD a NFQUEUE puedes además modificar.

## Verificar la captura

```
tcpdump -i any -n port 3306 -A          # ver payload MySQL en claro
tshark  -i any -f 'tcp port 3306' -x    # hex + protocolo
```
