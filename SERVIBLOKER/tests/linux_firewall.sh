#!/usr/bin/env bash
# Validación aislada nft y rechazo de IP interna falsificada SIN IPsec.
# Requiere Linux root y dependencias Python; nunca ejecutar contra reglas del host.
set -euo pipefail
[ "$(id -u)" -eq 0 ] && [ "$(uname -s)" = Linux ] || { echo 'Necesita Linux root'; exit 2; }
python_bin=${PYTHON:-python3}
base=$(cd "$(dirname "$0")" && pwd)
scratch=$(mktemp -d)
gw="iblocker-gw-$$"; client="iblocker-cl-$$"; server="iblocker-sv-$$"
cleanup(){ ip netns del "$client" 2>/dev/null || true; ip netns del "$server" 2>/dev/null || true; ip netns del "$gw" 2>/dev/null || true; rm -rf "$scratch"; }
trap cleanup EXIT
"$python_bin" "$base/render_firewall_fixture.py" > "$scratch/rules.nft"
for ns in "$gw" "$client" "$server"; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
ip link add vclient type veth peer name vgw0
ip link set vclient netns "$client"; ip link set vgw0 netns "$gw"
ip link add vserver type veth peer name vgw1
ip link set vserver netns "$server"; ip link set vgw1 netns "$gw"
ip -n "$client" addr add 10.77.0.2/24 dev vclient; ip -n "$client" link set vclient up
ip -n "$gw" addr add 10.77.0.1/24 dev vgw0; ip -n "$gw" link set vgw0 up
ip -n "$server" addr add 198.18.0.2/24 dev vserver; ip -n "$server" link set vserver up
ip -n "$gw" addr add 198.18.0.1/24 dev vgw1; ip -n "$gw" link set vgw1 up
ip -n "$client" route add default via 10.77.0.1
ip -n "$server" route add 10.77.0.0/24 via 198.18.0.1
ip netns exec "$gw" sysctl -qw net.ipv4.ip_forward=1
# Confirmar que el camino de prueba funciona ANTES de aplicar reglas.
ip netns exec "$client" ping -q -c 1 -W 2 198.18.0.2 >/dev/null
ip netns exec "$gw" nft --check -f "$scratch/rules.nft"
ip netns exec "$gw" nft -f "$scratch/rules.nft"
if ip netns exec "$client" ping -q -c 1 -W 2 198.18.0.2 >/dev/null; then
 echo 'FALLO: IP interna sin autenticación IPsec atravesó guardia' >&2; exit 1
fi
ip netns exec "$gw" nft list table inet iblocker >/dev/null
echo 'OK: sintaxis/kernel nft, aplicación atómica y bloqueo sin reqid IPsec.'
echo 'Pendiente: IKEv2 autenticado, aceptación UNLOCKED y vencimiento con túnel real.'
