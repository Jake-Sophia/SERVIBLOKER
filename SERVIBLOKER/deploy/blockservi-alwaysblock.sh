#!/bin/sh
# Compatibility chain for existing VPN deployments. Filtering stays in DNS.
# Blanket Apple (17/8) and shared CDN rejects also break Apple authentication.
# Replace only this chain; preserve forwarding, authorization and DNS rules.
set -eu
iptables -w -N BLOCKSERVI-ALWAYS 2>/dev/null || iptables -w -S BLOCKSERVI-ALWAYS >/dev/null
rules_file=$(mktemp)
trap 'rm -f "$rules_file"' EXIT
cat > "$rules_file" <<'RULES'
*filter
-F BLOCKSERVI-ALWAYS
-A BLOCKSERVI-ALWAYS -j RETURN
COMMIT
RULES
iptables-restore --wait 10 --noflush --test < "$rules_file"
iptables-restore --wait 10 --noflush < "$rules_file"
