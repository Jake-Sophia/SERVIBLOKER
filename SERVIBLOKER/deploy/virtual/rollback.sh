#!/usr/bin/env bash
# Conservar la guardia hasta que la conexión se retire definitivamente.
set -euo pipefail
[ "${1:-}" = --apply-reviewed ] || { echo 'Uso: rollback.sh --apply-reviewed'; exit 2; }
systemctl disable --now iblocker-controller
swanctl --terminate --ike iblocker --timeout 10
# Las autorizaciones nft expiran en <=15s. No borrar tabla con nuevos clientes posibles.
echo 'Controlador detenido y SA terminadas. La tabla iblocker permanece cerrada.'
echo 'Retire/cierre la conexión iblocker antes de considerar borrar exclusivamente esa tabla.'
