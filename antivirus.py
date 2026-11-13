#!/usr/bin/env python3
"""Antivirus prototipo: escaner bajo demanda con firmas, heuristica y cuarentena.

Solo usa la biblioteca estandar de Python. No es un reemplazo de un
antivirus comercial: no tiene proteccion en tiempo real ni acceso kernel.

Uso:
    python3 antivirus.py <ruta> [--cuarentena DIR] [--json reporte.json]
    python3 antivirus.py . --sin-cuarentena

Codigos de salida: 0 limpio, 1 amenazas, 2 error.
"""

import argparse
import hashlib
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path

BASE = Path(__file__).resolve().parent

URL_RE = re.compile(rb"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOBLE_EXT_RE = re.compile(
    r"\.(pdf|doc|docx|xls|jpg|jpeg|png|mp3|mp4|txt|zip)\.(exe|sh|py|js|bat|cmd|apk|jar)$",
    re.IGNORECASE,
)


def cargar_firmas(ruta):
    with open(ruta, encoding="utf-8") as f:
        db = json.load(f)
    patrones = [(p["nombre"], re.compile(p["regex"])) for p in db["patrones"]]
    return {
        "hashes": set(db.get("hashes_maliciosos", [])),
        "eicar": db.get("eicar", "").encode(),
        "patrones": patrones,
        "permisos": db.get("permisos_riesgosos", []),
        "sdks": db.get("sdk_publicitarios", []),
    }


def analizar_apk(data, nombre, firmas):
    """Inspeccion basica de APK: manifiesto + nombres de entradas."""
    hallazgos = []
    try:
        with zipfile.ZipFile(Path(nombre)) as z:
            entradas = z.namelist()
            if "AndroidManifest.xml" not in entradas:
                return hallazgos
            manifiesto = z.read("AndroidManifest.xml")
    except (zipfile.BadZipFile, OSError):
        return hallazgos
    texto = manifiesto.decode("utf-8", errors="ignore")
    texto += manifiesto.decode("utf-16", errors="ignore")
    for perm in firmas["permisos"]:
        if perm in texto:
            hallazgos.append(("amenaza", "permiso_riesgoso", perm))
    blob = b" ".join(e.encode(errors="ignore") for e in entradas) + b" " + manifiesto
    for sdk in firmas["sdks"]:
        if sdk.encode() in blob:
            hallazgos.append(("amenaza", "sdk_publicitario", sdk))
    return hallazgos


def escanear_archivo(path, firmas, max_bytes):
    """Devuelve (amenazas, infos). Cada item: (tipo, detalle)."""
    amenazas, infos = [], []
    try:
        size = path.stat().st_size
        if size > max_bytes:
            infos.append(("omitido_por_tamano", f"{size} bytes"))
            return amenazas, infos
        data = path.read_bytes()
    except OSError as e:
        infos.append(("no_legible", str(e)))
        return amenazas, infos

    sha = hashlib.sha256(data).hexdigest()
    if sha in firmas["hashes"]:
        amenazas.append(("hash_bloqueado", sha[:16] + "..."))
    if firmas["eicar"] and firmas["eicar"] in data:
        amenazas.append(("archivo_prueba_eicar", "firma EICAR detectada"))

    texto = data.decode("utf-8", errors="ignore")
    for nombre, rx in firmas["patrones"]:
        if rx.search(texto):
            amenazas.append(("patron_sospechoso", nombre))

    if DOBLE_EXT_RE.search(path.name):
        amenazas.append(("doble_extension", path.suffix))

    urls = set(URL_RE.findall(data)) - {b"http://www.w3.org"}
    ips = set(IP_RE.findall(data))
    for u in sorted(urls)[:5]:
        infos.append(("url", u.decode(errors="ignore")[:80]))
    for ip in sorted(ips)[:5]:
        infos.append(("ip", ip.decode()))

    if path.suffix.lower() == ".apk" or (
        data[:2] == b"PK" and path.suffix.lower() == ".zip"
    ):
        for nivel, tipo, det in analizar_apk(data, str(path), firmas):
            (amenazas if nivel == "amenaza" else infos).append((tipo, det))

    return amenazas, infos


def poner_en_cuarentena(path, raiz, dir_cuarentena):
    destino = dir_cuarentena / path.name
    n = 1
    while destino.exists():
        destino = dir_cuarentena / f"{path.stem}_{n}{path.suffix}"
        n += 1
    dir_cuarentena.mkdir(parents=True, exist_ok=True)
    shutil.move(str(path), str(destino))
    return destino


def main():
    ap = argparse.ArgumentParser(description="Antivirus prototipo: escaner bajo demanda")
    ap.add_argument("ruta", help="Archivo o carpeta a escanear")
    ap.add_argument("--firmas", default=str(BASE / "signatures.json"))
    ap.add_argument("--cuarentena", default="cuarentena", help="Carpeta de cuarentena")
    ap.add_argument("--sin-cuarentena", action="store_true", help="Solo informar")
    ap.add_argument("--json", default=None, help="Guardar reporte JSON")
    ap.add_argument("--max-mb", type=int, default=100)
    args = ap.parse_args()

    try:
        firmas = cargar_firmas(args.firmas)
    except (OSError, json.JSONDecodeError, KeyError) as e:
        print(f"Error cargando firmas: {e}", file=sys.stderr)
        return 2

    raiz = Path(args.ruta)
    if not raiz.exists():
        print(f"No existe: {raiz}", file=sys.stderr)
        return 2
    archivos = [raiz] if raiz.is_file() else sorted(p for p in raiz.rglob("*") if p.is_file())

    reporte = {"ruta": str(raiz), "archivos": 0, "amenazas": 0, "detalles": []}
    dir_cuar = Path(args.cuarentena)

    for path in archivos:
        amenazas, infos = escanear_archivo(path, firmas, args.max_mb * 1024 * 1024)
        reporte["archivos"] += 1
        if not amenazas and not infos:
            continue
        estado = "AMENAZA" if amenazas else "info"
        print(f"[{estado}] {path}")
        for tipo, det in amenazas:
            print(f"    - {tipo}: {det}")
        for tipo, det in infos:
            print(f"    (i) {tipo}: {det}")
        item = {"archivo": str(path), "amenazas": amenazas, "info": infos}
        if amenazas:
            reporte["amenazas"] += 1
            if not args.sin_cuarentena:
                try:
                    destino = poner_en_cuarentena(path, raiz, dir_cuar)
                    print(f"    -> cuarentena: {destino}")
                    item["cuarentena"] = str(destino)
                except OSError as e:
                    print(f"    -> no se pudo aislar: {e}")
        reporte["detalles"].append(item)

    print(f"\nArchivos: {reporte['archivos']}, con amenazas: {reporte['amenazas']}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(reporte, f, ensure_ascii=False, indent=2)
        print(f"Reporte: {args.json}")
    return 1 if reporte["amenazas"] else 0


if __name__ == "__main__":
    sys.exit(main())
