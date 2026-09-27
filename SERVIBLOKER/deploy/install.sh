#!/usr/bin/env bash
# Instala blockservi en un VPS Debian o Ubuntu.
# Uso: sudo ./install.sh ruta/al/blockservi.ini
set -euo pipefail

CONFIG_ORIGEN="${1:-}"
if [ -z "$CONFIG_ORIGEN" ] || [ ! -f "$CONFIG_ORIGEN" ]; then
	echo "Uso: sudo $0 /ruta/blockservi.ini" >&2
	exit 2
fi

ORIGEN="$(cd "$(dirname "$0")/.." && pwd)"
DOMINIO="$(grep -E '^domain' "$CONFIG_ORIGEN" | head -1 | cut -d= -f2 | tr -d ' ')"
DOMINIO_PORTAIL="$(grep -E '^portal_host' "$CONFIG_ORIGEN" | head -1 | cut -d= -f2 | tr -d ' ')"
SUFIJO="$(grep -E '^device_dns_suffix' "$CONFIG_ORIGEN" | head -1 | cut -d= -f2 | tr -d ' ')"

if [ "$(id -u)" -ne 0 ]; then
	echo "Este instalador necesita root." >&2
	exit 1
fi

echo "==> Instalando paquetes"
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip ca-certificates curl

echo "==> Creando usuario de servicio"
id -u blockservi >/dev/null 2>&1 || useradd --system --home /var/lib/blockservi --shell /usr/sbin/nologin blockservi

echo "==> Copiando el servicio a /opt/blockservi"
mkdir -p /opt/blockservi
rm -rf /opt/blockservi/blockservi
cp -r "$ORIGEN/blockservi" /opt/blockservi/
cp "$ORIGEN/requirements.txt" /opt/blockservi/
mkdir -p /var/lib/blockservi
if [ ! -f /var/lib/blockservi/policy.json ]; then
	cp "$ORIGEN/blockservi/policy.json" /var/lib/blockservi/policy.json
else
	echo "policy.json ya existe en /var/lib/blockservi, no se toca"
fi

echo "==> Creando el entorno de Python"
python3 -m venv /opt/blockservi/.venv
/opt/blockservi/.venv/bin/pip install -q --upgrade pip
/opt/blockservi/.venv/bin/pip install -q -r /opt/blockservi/requirements.txt

echo "==> Instalando la configuracion"
mkdir -p /etc/blockservi
install -m 640 -o root -g blockservi "$CONFIG_ORIGEN" /etc/blockservi/blockservi.ini
chown -R blockservi:blockservi /var/lib/blockservi
chmod 700 /var/lib/blockservi

echo "==> Creando el comando blockservi"
cat > /usr/local/bin/blockservi <<'WRAP'
#!/bin/sh
# -m blockservi solo encuentra el paquete si el directorio actual es /opt/blockservi,
# asi que este envoltorio se encarga de eso y de poner la configuracion por defecto.
#
# Si lo llama root, baja al usuario del servicio. Si no, el CLI escribiria
# devices.json como root y el servicio, que corre sin privilegios, no podria
# leerlo: los dispositivos parecerian no existir.
cd /opt/blockservi || exit 1
set -- --config "${BLOCKSERVI_CONFIG:-/etc/blockservi/blockservi.ini}" ${1+"$@"}
if [ "$(id -u)" = "0" ] && id -u blockservi >/dev/null 2>&1; then
	exec runuser -u blockservi -- /opt/blockservi/.venv/bin/python -m blockservi "$@"
fi
exec /opt/blockservi/.venv/bin/python -m blockservi "$@"
WRAP
chmod 755 /usr/local/bin/blockservi

echo "==> Registrando el servicio"
install -m 644 "$ORIGEN/deploy/blockservi.service" /etc/systemd/system/blockservi.service
systemctl daemon-reload
# Ojo: "enable --now" NO reinicia un servicio que ya esta activo, asi que se
# desplegaba el codigo nuevo y seguia corriendo el proceso viejo. Hay que
# reiniciar a proposito.
systemctl enable blockservi >/dev/null 2>&1 || true
systemctl restart blockservi
sleep 2
if systemctl is-active --quiet blockservi; then
	echo "    servicio activo, arrancado $(systemctl show blockservi -p ExecMainStartTimestamp --value)"
else
	echo "    ERROR: el servicio no arranca" >&2
	systemctl --no-pager status blockservi | head -20 >&2
	journalctl -u blockservi -n 30 --no-pager >&2
	exit 1
fi

cat <<AVISO

Listo. Falta el reverse proxy con TLS para:
  https://$DOMINIO_PORTAIL
  https://dev-<token>.$SUFIJO/dns-query

Copia deploy/Caddyfile a /etc/caddy/Caddyfile sustituyendo $DOMINIO, o
deploy/nginx.conf a /etc/nginx/sites-available/ si ya usas Nginx.

En Cloudflare (ambos en DNS only, nube gris):
  - $DOMINIO_PORTAIL -> A al VPS
  - $SUFIJO          -> A al VPS   (lo necesita Let's Encrypt para validar el comodin)
  - *.$SUFIJO        -> A al VPS   (cubre cada telefono: dev-<token>.$SUFIJO)

Comprueba el servicio con:
  curl -s http://127.0.0.1:8080/salud

AVISO
