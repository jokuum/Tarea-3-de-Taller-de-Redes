#!/usr/bin/env python3
"""
sniffer.py — captura definitiva de tráfico MySQL (Tarea 3, spec §4).

A diferencia de sniff_test.py (prueba de humo), este es el script de captura
que genera la evidencia central del punto "Interceptar con Scapy el tráfico
generado entre sus aplicaciones":

  - Captura filtrada por puerto MySQL (tcp port 3306), iface fijo y verificado.
  - Parsea el header MySQL por posición (parsear_mysql_header, exportable).
  - Clasifica cada paquete por tipo de mensaje MySQL.
  - Persiste evidencia: .pcap (para Wireshark) + log de texto (para citar).
  - Imprime un resumen final por tipo de mensaje.

También expone parsear_mysql_header() para que mitm_nfqueue.py y fuzzing.py
importen el parser en vez de duplicarlo (único punto de verdad del formato).

Uso:
    docker exec -it scapy_mitm python3 /scripts/sniffer.py --duracion 60
"""
import argparse
import time
from datetime import datetime

from scapy.all import sniff, Raw, TCP, get_if_list
from scapy.utils import wrpcap


# ─── PARSER DEL HEADER MYSQL (función exportable, único punto de verdad) ──────
def parsear_mysql_header(payload: bytes):
    """
    Parsea los 5 bytes de header del protocolo MySQL:
        [3 bytes largo (little-endian)] [1 byte sequence_id] [1 byte comando]
    Devuelve (largo, seq_id, comando, resto) o None si el payload es muy corto.

    'comando' solo es un comando MySQL válido en paquetes cliente->servidor
    (fase de comandos). En respuestas del servidor ese 5º byte es el primer
    byte del cuerpo de respuesta (0x00 OK, 0xFF error, 0xFE EOF, o el header
    del resultset). El llamador decide la interpretación según la dirección.
    """
    if len(payload) < 5:
        return None
    largo = int.from_bytes(payload[0:3], "little")
    seq_id = payload[3]
    comando = payload[4]
    resto = payload[5:]
    return largo, seq_id, comando, resto


# Comandos MySQL relevantes (subconjunto).
COM_QUERY = 0x03
COM_QUIT = 0x01
COM_INIT_DB = 0x02


def clasificar(pkt, puerto_servidor=3306):
    """
    Clasifica un paquete MySQL en: handshake / query / resultset / error / otro.
    Usa la dirección (según puerto TCP) para saber si el 5º byte es comando
    (cliente->servidor) o primer byte de respuesta (servidor->cliente).
    Devuelve (tipo, parsed) donde parsed es la tupla de parsear_mysql_header.
    """
    if not pkt.haslayer(Raw) or not pkt.haslayer(TCP):
        return "otro", None

    payload = bytes(pkt[Raw].load)
    parsed = parsear_mysql_header(payload)
    if parsed is None:
        return "otro", None

    _largo, seq_id, quinto, _resto = parsed
    desde_servidor = pkt[TCP].sport == puerto_servidor

    if desde_servidor:
        # Server greeting: primer paquete del servidor, seq_id 0, byte de
        # versión de protocolo 0x0a. Error packet: 0xFF como primer byte.
        if quinto == 0xFF:
            return "error", parsed
        if seq_id == 0 and quinto == 0x0A:
            return "handshake", parsed
        return "resultset", parsed
    else:
        if quinto == COM_QUERY:
            return "query", parsed
        return "otro", parsed


def main():
    parser = argparse.ArgumentParser(description="Captura y parsea tráfico MySQL (Tarea 3).")
    parser.add_argument("--iface", default="eth0", help="Interfaz de captura (default: eth0)")
    parser.add_argument("--duracion", type=int, default=60, help="Segundos de captura (default: 60)")
    parser.add_argument("--output", default="/scripts/captura_mysql.pcap", help="Ruta del .pcap de salida")
    parser.add_argument("--log", default="/scripts/log_captura.txt", help="Ruta del log de texto")
    parser.add_argument("--puerto-servidor", type=int, default=3306, help="Puerto TCP del servidor MySQL")
    args = parser.parse_args()

    if args.iface not in get_if_list():
        raise RuntimeError(
            f"Interfaz {args.iface} no existe. Interfaces disponibles: {get_if_list()}"
        )

    capturados = []
    conteo = {"handshake": 0, "query": 0, "resultset": 0, "error": 0, "otro": 0}
    logf = open(args.log, "a")

    def procesar(pkt):
        capturados.append(pkt)
        tipo, parsed = clasificar(pkt, args.puerto_servidor)
        conteo[tipo] += 1

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        if parsed is not None:
            largo, seq_id, quinto, resto = parsed
            linea = (
                f"{ts} | tipo={tipo:9s} | seq={seq_id:3d} | byte5=0x{quinto:02x} "
                f"| largo={largo} | data={resto[:60]!r}"
            )
        else:
            linea = f"{ts} | tipo={tipo:9s} | {pkt.summary()}"

        print(linea)
        logf.write(linea + "\n")

    print(f"[*] Capturando tcp port 3306 en {args.iface} por {args.duracion}s (Ctrl+C para cortar)...")
    inicio = time.time()
    try:
        sniff(
            filter="tcp port 3306",
            iface=args.iface,
            prn=procesar,
            store=0,
            timeout=args.duracion,
        )
    except KeyboardInterrupt:
        print("\n[*] Captura interrumpida por el usuario.")
    finally:
        logf.close()

    duracion_real = time.time() - inicio

    if capturados:
        wrpcap(args.output, capturados)
        print(f"[*] {len(capturados)} paquetes escritos a {args.output}")
    else:
        print("[!] No se capturó ningún paquete (¿había tráfico?, ¿iface correcta?).")

    print("\n=== RESUMEN DE CAPTURA ===")
    print(f"Duración: {duracion_real:.1f}s | Total paquetes: {len(capturados)}")
    for tipo, n in conteo.items():
        print(f"  {tipo:10s}: {n}")
    print(f"Log de texto: {args.log}")


if __name__ == "__main__":
    main()
