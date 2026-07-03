#!/usr/bin/env python3
"""
barrido.py — barrido de una métrica de red para encontrar su cota de desempeño
y medir el throughput aplicativo en cada punto (Tarea 3, spec §7).

Métricas soportadas (spec §7.1, decisión tomada): delay y loss, inyectadas con
tc + netem sobre la interfaz compartida con el cliente CloudBeaver.

Throughput: APLICATIVO (spec §7.4, decisión tomada). Por cada valor de la
métrica se captura el tráfico 3306 mientras se ejecuta una carga de trabajo fija
(una query repetida M veces contra mariadb_server) y se calcula:

        throughput = (bytes de payload MySQL en la ventana) / (duración)

La COTA de desempeño (spec §7.3) es el primer valor del barrido en el que la
carga de trabajo falla (la query no completa: error o timeout).

Salida: metricas/resultados_<metrica>.csv con columnas
        metrica,valor,throughput_bps,latencia_query_ms,estado

Uso (dentro del contenedor scapy_mitm):
    python3 /scripts/metricas/barrido.py --metrica delay --valores 0 50 100 200 400 800 1600
    python3 /scripts/metricas/barrido.py --metrica loss  --valores 0 1 5 10 20 40 60

Requiere: tc (iproute2) + NET_ADMIN (ya en el contenedor) y el cliente mysql
(mariadb-client, ver Dockerfile). Corre con el sniffer.py del mismo repo.
"""
import argparse
import csv
import os
import subprocess
import sys
import time

# sniffer.py está un nivel arriba (/scripts). Lo agregamos al path para reutilizar
# su parser y su clasificación sin duplicar código.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import AsyncSniffer, Raw  # noqa: E402


# ─── INYECCIÓN DE LA MÉTRICA CON netem ───────────────────────────────────────
def aplicar_metrica(iface, metrica, valor):
    _limpiar(iface)
    if metrica == "delay":
        spec = ["delay", f"{valor}ms"]
    elif metrica == "loss":
        spec = ["loss", f"{valor}%"]
    else:
        raise ValueError(f"Métrica no soportada: {metrica}")
    # valor 0 = línea base sin degradación real, igual aplicamos el qdisc.
    subprocess.run(
        ["tc", "qdisc", "add", "dev", iface, "root", "netem"] + spec,
        check=True,
    )


def _limpiar(iface):
    # Borra el qdisc netem si existe; ignora el error si no había ninguno.
    subprocess.run(
        ["tc", "qdisc", "del", "dev", iface, "root"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


# ─── CARGA DE TRABAJO ────────────────────────────────────────────────────────
def correr_query(host, usuario, password, base, query, timeout):
    """
    Ejecuta una query con el cliente mysql. Devuelve (ok, latencia_ms).
    ok=False si la query falla o excede el timeout (candidato a cota).
    """
    cmd = [
        "mysql", f"-h{host}", f"-u{usuario}", f"-p{password}",
        "--connect-timeout", str(int(timeout)), base, "-e", query,
    ]
    t0 = time.time()
    try:
        r = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=timeout,
        )
        latencia = (time.time() - t0) * 1000.0
        return (r.returncode == 0), latencia
    except subprocess.TimeoutExpired:
        return False, timeout * 1000.0


def medir_punto(iface, host, usuario, password, base, query, repeticiones, timeout):
    """
    Captura el tráfico 3306 mientras corre la carga; devuelve
    (throughput_bps, latencia_media_ms, estado).
    """
    sniffer = AsyncSniffer(filter="tcp port 3306", iface=iface, store=True)
    sniffer.start()
    time.sleep(0.3)  # que el sniffer esté listo antes de generar tráfico

    t0 = time.time()
    latencias = []
    fallos = 0
    for _ in range(repeticiones):
        ok, lat = correr_query(host, usuario, password, base, query, timeout)
        latencias.append(lat)
        if not ok:
            fallos += 1
    duracion = time.time() - t0

    time.sleep(0.3)
    paquetes = sniffer.stop()

    total_bytes = sum(len(p[Raw].load) for p in paquetes if p.haslayer(Raw))
    throughput_bps = (total_bytes * 8) / duracion if duracion > 0 else 0.0
    latencia_media = sum(latencias) / len(latencias) if latencias else 0.0
    # Estado: 'ok' si todas completaron; 'degradado'/'fallo' según cuántas cayeron.
    if fallos == 0:
        estado = "ok"
    elif fallos < repeticiones:
        estado = "degradado"
    else:
        estado = "fallo"
    return throughput_bps, latencia_media, estado


def main():
    parser = argparse.ArgumentParser(description="Barrido de métrica de red vs throughput (Tarea 3).")
    parser.add_argument("--metrica", choices=["delay", "loss"], required=True)
    parser.add_argument("--valores", type=float, nargs="+", required=True,
                        help="Lista creciente de valores (ms para delay, %% para loss).")
    parser.add_argument("--iface", default="eth0")
    parser.add_argument("--host", default="mariadb_server")
    parser.add_argument("--usuario", default="usuario")
    parser.add_argument("--password", default="usuario_password")
    parser.add_argument("--base", default="taller_redes")
    parser.add_argument(
        "--query",
        default=(
            "SELECT p.id, p.contenido, COUNT(l.id) AS total_likes "
            "FROM posts p LEFT JOIN likes l ON p.id = l.post_id "
            "GROUP BY p.id ORDER BY total_likes DESC;"
        ),
        help="Carga de trabajo repetible (default: JOIN posts+likes del schema taller_redes).",
    )
    parser.add_argument("--repeticiones", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Timeout por query en segundos (define la cota).")
    parser.add_argument("--output", default=None,
                        help="CSV de salida (default: metricas/resultados_<metrica>.csv).")
    args = parser.parse_args()

    salida = args.output or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), f"resultados_{args.metrica}.csv"
    )

    print(f"[*] Barrido de '{args.metrica}' en {args.iface}. Valores: {args.valores}")
    filas = []
    cota = None
    try:
        for valor in args.valores:
            aplicar_metrica(args.iface, args.metrica, valor)
            thr, lat, estado = medir_punto(
                args.iface, args.host, args.usuario, args.password, args.base,
                args.query, args.repeticiones, args.timeout,
            )
            unidad = "ms" if args.metrica == "delay" else "%"
            print(f"  {args.metrica}={valor}{unidad:2s} | throughput={thr:,.0f} bps "
                  f"| lat_query={lat:,.0f} ms | estado={estado}")
            filas.append([args.metrica, valor, round(thr, 2), round(lat, 2), estado])
            if cota is None and estado != "ok":
                cota = valor
    finally:
        _limpiar(args.iface)
        print("[*] qdisc netem limpiado.")

    with open(salida, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["metrica", "valor", "throughput_bps", "latencia_query_ms", "estado"])
        w.writerows(filas)

    print(f"\n[*] Resultados escritos a {salida}")
    if cota is not None:
        print(f"[*] COTA DE DESEMPEÑO estimada: +{cota} "
              f"({'ms' if args.metrica == 'delay' else '%'}) "
              f"— primer valor con degradación/fallo.")
    else:
        print("[*] No se alcanzó la cota en el rango barrido: probá valores más altos.")


if __name__ == "__main__":
    main()
