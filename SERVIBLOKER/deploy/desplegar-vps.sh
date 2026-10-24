#!/usr/bin/env bash
# Despliegue completo de blockservi en 209.145.55.123 (unlockersserver.com).
# No interactivo. Idempotente. No borra nada: nginx se apaga y su configuracion
# se copia a /root/nginx-backup, pero sigue instalado para poder volver.
#
#   ssh root@209.145.55.123 'sh /tmp/blockservi/deploy/desplegar-vps.sh tu@correo.com'
set -uo pipefail

echo 'El despliegue histórico que detiene nginx se ha retirado por seguridad.' >&2
echo 'Use deploy/install.sh CONFIG --apply-reviewed e integre su proxy; vea docs/IBLOKER-VIRTUAL.md.' >&2
exit 2
