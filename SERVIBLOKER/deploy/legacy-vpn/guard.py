#!/usr/bin/env python3
"""Adaptador de un perfil legado: tabla propia, identidad y dirección fijas.

No usa permisos por IP pública ni la lista de desbloqueos web_id.
Los permisos caducan en el kernel si el proceso deja de actualizarse.
"""
import ipaddress
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

TABLE = 'iblocker_delivery'
POOL4 = '10.77.10.0/24'
POOL6 = 'fd77:77:10::/120'
IP4 = '10.77.10.10'
IP6 = 'fd77:77:10::10'
DNS = '10.77.10.1'
SERVER = '209.145.55.123'
REQID = 77010


def nft(script, check=False):
    args = ['nft'] + (['--check'] if check else []) + ['-f', '-']
    subprocess.run(args, input=script, text=True, check=True, capture_output=True, timeout=5)


def rules(require_ipsec=True):
    inbound = f'ipsec in reqid {REQID} ' if require_ipsec else ''
    outbound = f'ipsec out reqid {REQID} ' if require_ipsec else ''
    return f'''table inet {TABLE} {{
 set unlocked4 {{ type ipv4_addr; flags timeout; }}
 set unlocked6 {{ type ipv6_addr; flags timeout; }}
 chain input {{ type filter hook input priority -30; policy accept;
  ip saddr {POOL4} jump fromclient
  ip6 saddr {POOL6} jump fromclient
 }}
 chain fromclient {{
  ip saddr {IP4} {inbound}ip daddr {SERVER} tcp dport 443 counter accept
  ip saddr {IP4} {inbound}ip daddr {DNS} udp dport 53 counter accept
  ip saddr {IP4} {inbound}ip daddr {DNS} tcp dport 53 counter accept
  counter drop
 }}
 chain forward {{ type filter hook forward priority -30; policy accept;
  ip saddr {POOL4} jump fromvpn
  ip6 saddr {POOL6} jump fromvpn
  ip daddr {POOL4} jump tovpn
  ip6 daddr {POOL6} jump tovpn
 }}
 chain fromvpn {{
  ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4 }} counter drop
  ip6 daddr {{ ::/128, ::1/128, fc00::/7, fe80::/10, ff00::/8 }} counter drop
  ip saddr @unlocked4 {inbound}counter accept
  ip6 saddr @unlocked6 {inbound}counter accept
  counter drop
 }}
 chain tovpn {{
  ip daddr @unlocked4 {outbound}ct state established,related counter accept
  ip6 daddr @unlocked6 {outbound}ct state established,related counter accept
  counter drop
 }}
 chain nat4 {{ type nat hook postrouting priority srcnat; policy accept;
  ip saddr {POOL4} masquerade
 }}
 chain nat6 {{ type nat hook postrouting priority srcnat; policy accept;
  ip6 saddr {POOL6} masquerade
 }}
}}
'''


def permission(data, token, now):
    if (data.get('token') != token or data.get('error') or
            data.get('conocido') is False or data.get('modo') != 'unlocked'):
        return 0
    # Este adaptador no confía en desbloqueos heredados por IP ni navegador.
    return max(0, min(5, int(data.get('desbloqueado_hasta') or 0) - now))


def refresh(token):
    try:
        with urllib.request.urlopen('http://127.0.0.1:8080/api/pedido/' + token, timeout=2) as response:
            data = json.loads(response.read(65536))
        ttl = permission(data, token, int(time.time()))
    except (OSError, ValueError, TypeError, AttributeError):
        ttl = 0
    script = f'flush set inet {TABLE} unlocked4\nflush set inet {TABLE} unlocked6\n'
    if ttl:
        script += f'add element inet {TABLE} unlocked4 {{ {IP4} timeout {ttl}s }}\n'
        script += f'add element inet {TABLE} unlocked6 {{ {IP6} timeout {ttl}s }}\n'
    nft(script)


def serve_dns(token):
    from dnslib import DNSRecord, RCODE
    from dnslib.server import BaseResolver, DNSLogger, DNSServer

    class Resolver(BaseResolver):
        def resolve(self, query, handler):
            # Se vincula siempre al perfil asignado a esta IP interna.
            if str(handler.client_address[0]) != IP4:
                reply = query.reply()
                reply.header.rcode = RCODE.REFUSED
                return reply
            request = urllib.request.Request(
                'http://127.0.0.1:8080/dns-query', data=query.pack(),
                headers={'Host': f'dev-{token}.dns.unlockersserver.com',
                         'Content-Type': 'application/dns-message',
                         'X-Forwarded-For': IP4})
            try:
                with urllib.request.urlopen(request, timeout=4) as response:
                    return DNSRecord.parse(response.read(65536))
            except Exception:
                reply = query.reply()
                reply.header.rcode = RCODE.SERVFAIL
                return reply

    logger = DNSLogger(log='-request,-reply,-truncated,-error', prefix=False)
    servers = [DNSServer(Resolver(), address=DNS, port=53, tcp=tcp, logger=logger)
               for tcp in (False, True)]
    for server in servers:
        server.start_thread()
    return servers


def main():
    config = json.loads(Path('/etc/iblocker-delivery/config.json').read_text())
    token = config['token']
    if len(token) != 48 or any(c not in '0123456789abcdef' for c in token):
        raise ValueError('invalid identity')
    subprocess.run(['ip', 'address', 'replace', DNS + '/32', 'dev', 'lo'], check=True)
    exists = subprocess.run(['nft', 'list', 'table', 'inet', TABLE], capture_output=True).returncode == 0
    script = (f'delete table inet {TABLE}\n' if exists else '') + rules()
    nft(script, check=True)
    nft(script)
    servers = serve_dns(token)
    refresh(token)
    while True:
        refresh(token)
        if not all(server.isAlive() for server in servers):
            raise RuntimeError('DNS listener stopped')
        time.sleep(2)


if __name__ == '__main__':
    main()
