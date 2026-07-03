#!/usr/bin/env python3
"""
graficar.py — genera el gráfico métrica vs throughput a partir del CSV que
produce barrido.py (Tarea 3, spec §7.6).

Un gráfico por métrica (eje X = valor de la métrica, eje Y = throughput),
marcando la cota de desempeño (primer punto con estado != 'ok') con una línea
vertical roja.

Uso:
    python3 /scripts/metricas/graficar.py --csv metricas/resultados_delay.csv
    python3 /scripts/metricas/graficar.py --csv metricas/resultados_loss.csv

Requiere matplotlib (ver Dockerfile). Si se prefiere, puede correrse en el host
sobre los CSV descargados del contenedor.
"""
import argparse
import csv
import os

import matplotlib
matplotlib.use("Agg")  # backend sin display (contenedor headless)
import matplotlib.pyplot as plt  # noqa: E402


UNIDADES = {"delay": "ms", "loss": "%"}


def leer_csv(ruta):
    metrica = None
    valores, throughputs, estados = [], [], []
    with open(ruta, newline="") as f:
        for fila in csv.DictReader(f):
            metrica = fila["metrica"]
            valores.append(float(fila["valor"]))
            throughputs.append(float(fila["throughput_bps"]))
            estados.append(fila["estado"])
    return metrica, valores, throughputs, estados


def main():
    parser = argparse.ArgumentParser(description="Gráfico métrica vs throughput (Tarea 3).")
    parser.add_argument("--csv", required=True, help="CSV producido por barrido.py")
    parser.add_argument("--output", default=None, help="PNG de salida (default: <metrica>_vs_throughput.png)")
    args = parser.parse_args()

    metrica, valores, throughputs, estados = leer_csv(args.csv)
    unidad = UNIDADES.get(metrica, "")

    salida = args.output or os.path.join(
        os.path.dirname(os.path.abspath(args.csv)) or ".",
        f"{metrica}_vs_throughput.png",
    )

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(valores, throughputs, marker="o", color="#2563eb", label="throughput aplicativo")

    # Cota: primer punto con estado != 'ok'.
    cota = next((v for v, e in zip(valores, estados) if e != "ok"), None)
    if cota is not None:
        ax.axvline(cota, color="#dc2626", linestyle="--",
                   label=f"cota de desempeño = +{cota}{unidad}")

    ax.set_xlabel(f"{metrica} ({unidad})")
    ax.set_ylabel("throughput (bps)")
    ax.set_title(f"{metrica} vs throughput — servicio MySQL")
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(salida, dpi=120)
    print(f"[*] Gráfico escrito a {salida}"
          + (f" | cota marcada en +{cota}{unidad}" if cota is not None else " | sin cota en el rango"))


if __name__ == "__main__":
    main()
