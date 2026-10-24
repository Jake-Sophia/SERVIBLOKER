#!/usr/bin/env bash
# Inspección por defecto. No reemplaza servicios VPN/proxy existentes.
set -euo pipefail
mode=${1:---check}
case "$mode" in --check|--apply-reviewed) ;; *) echo 'Use --check o --apply-reviewed' >&2; exit 2;; esac
[ "$(id -u)" -eq 0 ] || { echo 'Ejecutar en el VPS como root'; exit 1; }
[ "$(uname -s)" = Linux ] || { echo 'Sólo Linux'; exit 1; }
echo 'Puertos actuales:'
ss -luntp
echo 'Reglas existentes:'
command -v nft >/dev/null && nft list ruleset || true
echo 'VPN existente:'
for unit in strongswan strongswan-starter ipsec; do systemctl is-active "$unit" || true; done
[ "$mode" = --apply-reviewed ] || { echo 'Sólo inspección. Revisar solapamiento de pools, puertos 500/4500, proxy y FORWARD antes de continuar.'; exit 0; }
# Ante VPN previa, exigir integración manual; no detener ni sustituir servicios.
for unit in strongswan strongswan-starter ipsec; do
 if systemctl is-active --quiet "$unit"; then echo "VPN existente ($unit): integrar manualmente, sin instalación automática" >&2; exit 1; fi
done
if ss -H -lun | awk '{print $4}' | grep -Eq ':(500|4500)$'; then
 echo 'Puertos IKE ocupados; no se modifica nada' >&2; exit 1
fi
if [ -d /etc/swanctl/conf.d ] && find /etc/swanctl/conf.d -name "*.conf" -type f | grep -q .; then
 echo "Configuración VPN existente: integrar manualmente" >&2; exit 1
fi
apt-get update
apt-get install -y strongswan-swanctl charon-systemd libcharon-extra-plugins nftables
src=$(cd "$(dirname "$0")" && pwd)
[ -f /etc/blockservi/blockservi.ini ] || { echo 'Instalar primero SERVIBLOKER con configuración local'; exit 1; }
install -d -m 755 /etc/swanctl/conf.d
# Sólo se dejan ejemplos y unidad INACTIVA. PKI y carga son pasos explícitos.
install -m 600 "$src/swanctl.conf.example" /etc/blockservi/iblocker-swanctl.conf.example
install -m 600 "$src/firewall.json.example" /etc/blockservi/firewall.json.example
install -m 644 "$src/iblocker-controller.service" /etc/systemd/system/iblocker-controller.service
install -m 644 "$src/iblocker-guard.service" /etc/systemd/system/iblocker-guard.service
systemctl daemon-reload
echo 'Preparado. No se ha activado el controlador ni cambiado reglas. Seguir docs/IBLOKER-VIRTUAL.md.'
