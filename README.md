# Antivirus prototipo

Escáner bajo demanda con firmas, heurística básica y cuarentena.
Solo usa la biblioteca estándar de Python 3, sin dependencias.

## Qué analiza

- Hash SHA256 contra lista de hashes maliciosos.
- Firma de prueba EICAR (estándar inofensivo para verificar detección).
- Patrones sospechosos en scripts y texto (ofuscación, shells reversas, etc.).
- Doble extensión (`factura.pdf.exe`).
- URLs e IPs embebidas (informativo).
- APKs: permisos riesgosos (`SYSTEM_ALERT_WINDOW`, instalación de paquetes,
  accesibilidad) y rastros de SDKs publicitarios agresivos (adware).

## Uso

```bash
python3 antivirus.py <ruta>
python3 antivirus.py ~/Downloads --json reporte.json
python3 antivirus.py . --sin-cuarentena   # solo informa, no aísla
```

Códigos de salida: `0` limpio, `1` amenazas, `2` error.

Los archivos con amenazas se mueven a `./cuarentena/`.

## Probar detección (EICAR, inofensivo)

```bash
printf 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
python3 antivirus.py /tmp/eicar.txt --sin-cuarentena
```

## Límites honestos

Sin protección en tiempo real, sin acceso kernel, sin sandbox dinámico
ni red global de amenazas. Útil como segunda opinión y laboratorio,
no como reemplazo de un antivirus comercial. En Android sin root no
puede inspeccionar datos privados de otras apps ni desinstalarlas.
