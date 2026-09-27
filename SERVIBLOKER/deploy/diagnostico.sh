#!/bin/sh
# Diagnostico del VPS: que hay en nginx, que certificados, si hay firewall.
echo "=== identity"
hostname
id -un
echo
echo "=== nginx activo?"
systemctl is-active nginx 2>/dev/null || echo "no"
echo
echo "=== sites-enabled"
ls -l /etc/nginx/sites-enabled/ 2>/dev/null || echo "no existe la carpeta"
echo
echo "=== puertos que escuchan"
ss -ltnp 2>/dev/null | grep -E ':(80|443|8080|8443|5353) ' || echo "ninguno en 80/443/8080"
echo
echo "=== certificados de certbot"
certbot certificates 2>/dev/null | grep -E "Certificate Name|Domains|Expiry" || echo "certbot no instalado o sin certificados"
echo
echo "=== caddy"
command -v caddy || echo "caddy no instalado"
echo
echo "=== codigo subido"
ls /tmp/blockservi 2>/dev/null || echo "/tmp/blockservi no esta"
echo
echo "=== units de blockservi"
systemctl is-active blockservi 2>/dev/null || echo "blockservi no instalado"
echo
echo "=== firewall"
ufw status 2>/dev/null | head -4 || echo "ufw no instalado"
iptables -L INPUT -n 2>/dev/null | head -5 || true
echo
echo "=== disco"
df -h / | tail -1
echo "=== fin"
