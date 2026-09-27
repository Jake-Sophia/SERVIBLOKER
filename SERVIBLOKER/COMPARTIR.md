# BlockServi - paquete para compartir

Este paquete contiene el codigo fuente del servicio, sin claves reales ni perfiles instalables generados.

## Incluye

- `blockservi/`: aplicacion Python del filtro, portal, perfiles y API.
- `tests/`: pruebas locales.
- `README.md`: documentacion del proyecto.
- `blockservi.ini.example`: ejemplo de configuracion.
- `perfiles/policy.json`: ejemplo de politica.

## No incluye

- `.venv/`
- caches `__pycache__`
- claves API/admin reales
- `blockservi.ini` real
- perfiles `.mobileconfig` generados
- datos de produccion

## Antes de usar

1. Copiar `blockservi.ini.example` a `blockservi.ini`.
2. Cambiar dominio, `admin_key`, usuarios/clave VPN y rutas.
3. Crear claves API nuevas.
4. No reutilizar claves del servidor original.

## Pruebas

```bash
python -m venv .venv
. .venv/bin/activate
pip install aiohttp dnslib ruff
python -m ruff check blockservi/ tests/ --select F,E9
python tests/test_blockservi.py
```
