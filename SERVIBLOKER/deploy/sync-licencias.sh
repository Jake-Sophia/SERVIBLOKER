#!/usr/bin/env bash
# Copia licenses.json del panel PHP al VPS.
# El servicio lo relee solo cuando cambia el fichero, sin reiniciar nada.
#
#   ./deploy/sync-licencias.sh [usuario@host]
#   BLOCKSERVI_SSH_KEY=~/.ssh/miclave ./deploy/sync-licencias.sh
set -euo pipefail

ORIGEN="$(cd "$(dirname "$0")/.." && pwd)/../data/licenses.json"
DESTINO="${1:-root@209.145.55.123}"
CLAVE="${BLOCKSERVI_SSH_KEY:-}"
EXTRA=()
[ -n "$CLAVE" ] && EXTRA=(-i "$CLAVE" -o BatchMode=yes)

if [ ! -f "$ORIGEN" ]; then
	echo "No encuentro $ORIGEN" >&2
	exit 1
fi

scp -q "${EXTRA[@]}" "$ORIGEN" "$DESTINO:/var/lib/blockservi/licenses.json.tmp"
ssh "${EXTRA[@]}" "$DESTINO" \
	'mv /var/lib/blockservi/licenses.json.tmp /var/lib/blockservi/licenses.json
	 chown blockservi:blockservi /var/lib/blockservi/licenses.json
	 echo "licencias sincronizadas: $(python3 -c "import json;print(len(json.load(open(\"/var/lib/blockservi/licenses.json\"))))") codigos"'
