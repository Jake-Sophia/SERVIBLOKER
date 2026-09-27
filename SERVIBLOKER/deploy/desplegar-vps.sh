#!/usr/bin/env bash
# Despliegue completo de blockservi en 209.145.55.123 (unlockersserver.com).
# No interactivo. Idempotente. No borra nada: nginx se apaga y su configuracion
# se copia a /root/nginx-backup, pero sigue instalado para poder volver.
#
#   ssh root@209.145.55.123 'sh /tmp/blockservi/deploy/desplegar-vps.sh tu@correo.com'
set -uo pipefail

ORIGEN="$(cd "$(dirname "$0")/.." && pwd)"
CORREO="${1:-root@localhost}"
FALLOS=0

log()  { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
ok()   { printf '    [ok] %s\n' "$1"; }
mal()  { printf '    [!!] %s\n' "$1"; FALLOS=$((FALLOS+1)); }

[ "$(id -u)" -eq 0 ] || { echo "Necesita root." >&2; exit 1; }
[ -f "$ORIGEN/deploy/blockservi.ini.produccion" ] || { echo "Falta la configuracion en $ORIGEN" >&2; exit 1; }

# --------------------------------------------------------------- inventario
log "Que hay ahora mismo en el servidor"
echo "    sites de nginx:"
ls /etc/nginx/sites-enabled/ 2>/dev/null | sed 's/^/      /' || echo "      (ninguno)"
echo "    puertos ocupados:"
ss -ltn 2>/dev/null | awk 'NR>1{print "      "$4}' | head -10

# --------------------------------------------------------------- nginx
if systemctl is-active --quiet nginx 2>/dev/null; then
	log "Apartando nginx (copia de seguridad en /root/nginx-backup)"
	mkdir -p /root/nginx-backup
	cp -a /etc/nginx /root/nginx-backup/ 2>/dev/null && ok "config copiada"
	systemctl stop nginx && ok "nginx parado"
	systemctl disable nginx >/dev/null 2>&1
	cat > /root/REVERTIR-NGINX.txt <<'NOTA'
El 80 y el 443 los lleva ahora Caddy, para blockservi.

Para volver a tu sitio de /var/www/vpn (que sirve profile.mobileconfig):

  systemctl stop caddy && systemctl disable caddy
  systemctl unmask nginx 2>/dev/null
  systemctl start nginx

Lo que habia antes:

  server_name vpn.unlockersserver.com
  root /var/www/vpn
  /profile.mobileconfig  ->  /var/www/vpn/profile.mobileconfig
  cert: /etc/letsencrypt/live/vpn.unlockersserver.com (vence el 24/12/2026)

Ojo: vpn.unlockersserver.com no tiene registro DNS, por eso ese sitio no
era accesible desde internet. Si quieres volver a publicarlo, hay que crear
el registro A y volver a emitting el certificado.
NOTA
	ok "nginx sigue instalado; como volver atras esta en /root/REVERTIR-NGINX.txt"
else
	ok "nginx no estaba activo"
fi

# --------------------------------------------------------------- Caddy
log "Instalando Caddy"
if command -v caddy >/dev/null 2>&1; then
	ok "ya estaba instalado"
else
	apt-get update -qq 2>&1 | tail -1
	apt-get install -y -qq ca-certificates curl 2>&1 | tail -1
	CV=$(curl -fsSL https://api.github.com/repos/caddyserver/caddy/releases/latest 2>/dev/null | grep -oE '"tag_name": *"v[0-9.]+"' | head -1 | tr -dc '0-9.')
	if [ -n "$CV" ] && curl -fL --retry 3 -s -o /tmp/caddy.deb "https://github.com/caddyserver/caddy/releases/download/v$CV/caddy_${CV}_linux_amd64.deb"; then
		apt-get install -y -qq /tmp/caddy.deb 2>&1 | tail -2
		ok "instalado el .deb oficial $CV"
	else
		mal "no se pudo instalar Caddy"
	fi
fi
command -v caddy >/dev/null 2>&1 && ok "caddy $(caddy version 2>/dev/null | head -1)" || mal "caddy no esta en el PATH"

# --------------------------------------------------------------- servicio
log "Instalando blockservi"
bash "$ORIGEN/deploy/install.sh" "$ORIGEN/deploy/blockservi.ini.produccion" 2>&1 | sed 's/^/    /'
[ -x /opt/blockservi/.venv/bin/python ] && ok "venv creado" || mal "no hay venv en /opt/blockservi"
systemctl is-active --quiet blockservi && ok "servicio arrancado" || mal "el servicio no arranca: journalctl -u blockservi -n 40"

if [ -f /tmp/licenses.json ]; then
	cp /tmp/licenses.json /var/lib/blockservi/licenses.json
	chown blockservi:blockservi /var/lib/blockservi/licenses.json
	ok "licencias copiadas ($(python3 -c 'import json;print(len(json.load(open("/var/lib/blockservi/licenses.json"))))' 2>/dev/null || echo '?') codigos)"
else
	mal "no hay /tmp/licenses.json: los codigos no funcionaran hasta copiarlo"
fi

# --------------------------------------------------------------- Caddyfile
log "Configurando Caddy para unlockersserver.com"
id -u caddy >/dev/null 2>&1 && install -d -o caddy -g caddy /var/log/caddy || mkdir -p /var/log/caddy
# El servicio (blockservi) escribe los host de cada dispositivo y Caddy los lee.
install -d -o blockservi -g caddy -m 2775 /etc/caddy/dispositivos
cp "$ORIGEN/deploy/Caddyfile" /etc/caddy/Caddyfile
sed -i "s/PON-TU-CORREO-AQUI/$CORREO/" /etc/caddy/Caddyfile
grep -q 'unlockersserver.com' /etc/caddy/Caddyfile && ok "Caddyfile listo" || mal "el Caddyfile no menciona el dominio"

systemctl restart caddy 2>&1 | tail -1
sleep 2
systemctl is-active --quiet caddy && ok "caddy activo" || mal "caddy no arranca: journalctl -u caddy -n 30"

# --------------------------------------------------------------- certificados
log "Pidiendo certificados (puede tardar un minuto)"
for i in $(seq 1 20); do
	if curl -sf --max-time 5 https://vpnk.unlockersserver.com/salud >/dev/null 2>&1; then
		ok "el portal ya responde"
		break
	fi
	sleep 6
done

echo
echo "    certificado del portal:"
echo | openssl s_client -connect vpnk.unlockersserver.com:443 -servername vpnk.unlockersserver.com 2>/dev/null \
	| openssl x509 -noout -subject -dates 2>/dev/null | sed 's/^/      /' || mal "sin certificado"

echo "    certificado de un dispositivo:"
DEV=$(ls /etc/caddy/dispositivos/*.caddy 2>/dev/null | head -1 | xargs -r grep -hoE 'dev-[0-9a-f]+' | head -1)
if [ -n "$DEV" ]; then
	echo | openssl s_client -connect "$DEV.dns.unlockersserver.com:443" -servername "$DEV.dns.unlockersserver.com" 2>/dev/null \
		| openssl x509 -noout -subject -dates 2>/dev/null | sed 's/^/      /' || mal "sin certificado"
else
	ok "aun no hay dispositivos dados de alta"
fi

# --------------------------------------------------------------- resumen
log "Resumen"
printf '    portal   %s\n' "$(curl -s --max-time 8 https://vpnk.unlockersserver.com/salud || echo SIN RESPUESTA)"
printf '    servicio %s\n' "$(systemctl is-active blockservi 2>/dev/null)"
printf '    caddy    %s\n' "$(systemctl is-active caddy 2>/dev/null)"

if [ "$FALLOS" -eq 0 ]; then
	log "Todo en orden"
else
	log "Hubo $FALLOS problema(s). Copia el texto de arriba y lo miramos."
fi
echo
echo "Siguiente paso: registrar un telefono"
echo "  /opt/blockservi/.venv/bin/python -m blockservi --config /etc/blockservi/blockservi.ini device add --label Recepcion"
