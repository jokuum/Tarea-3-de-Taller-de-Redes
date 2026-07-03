#!/usr/bin/env python3
"""
Sniff pasivo de tráfico MySQL (puerto 3306).

Este script solo OBSERVA: no modifica ni reinyecta paquetes. Sirve para
confirmar que, al compartir la pila de red del cliente CloudBeaver
(network_mode: service:cliente), el tráfico MySQL cliente<->servidor pasa
por esta netns y Scapy lo puede ver.

Corre durante 60 segundos o hasta que se interrumpa con Ctrl+C.
"""
from scapy.all import sniff, Raw

# Segundos que dura la captura antes de terminar sola.
DURACION = 60


def procesar(pkt):
    # Resumen de una línea del paquete (IPs, puertos, flags TCP).
    print(pkt.summary())

    # Si el paquete lleva datos de aplicación (capa Raw), es donde viaja el
    # protocolo MySQL en claro. Mostramos los primeros bytes en hexadecimal.
    if pkt.haslayer(Raw):
        datos = bytes(pkt[Raw].load)
        print(f"    payload[{len(datos)}B]: {datos[:32].hex()}")


print(f"[*] Capturando tcp port 3306 por {DURACION}s (Ctrl+C para cortar antes)...")
try:
    # filter usa sintaxis BPF; store=0 evita acumular paquetes en memoria.
    sniff(filter="tcp port 3306", prn=procesar, store=0, timeout=DURACION)
except KeyboardInterrupt:
    print("\n[*] Captura interrumpida por el usuario.")

print("[*] Fin de la captura.")
