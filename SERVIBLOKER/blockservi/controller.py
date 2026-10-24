"""Controlador privilegiado opt-in. Sólo tabla nft propia; VICI mediante socket root."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pwd
import socket
import subprocess
import time
from pathlib import Path

from .config import load
from .persistence import file_lock
from .pki import Authority
from .rules import MODE_STRICT, Policy
from .store import Store
from .virtual import VirtualState


def decoded(value):
    if isinstance(value, bytes):
        return value.decode()
    if isinstance(value, dict):
        return {decoded(k): decoded(v) for k, v in value.items()}
    if isinstance(value, list):
        return [decoded(v) for v in value]
    return value


def sessions_from_vici(messages: list[dict]) -> list[dict]:
    result = []
    for message in messages:
        for name, sa in decoded(message).items():
            if name != "iblocker" or sa.get("state") != "ESTABLISHED":
                continue
            peer = sa.get("remote-id", "")
            suffix = ".iblocker.invalid"
            token = peer[:-len(suffix)] if peer.endswith(suffix) else ""
            from .profile import TOKEN_RE
            if not TOKEN_RE.fullmatch(token):
                continue
            for child in sa.get("child-sas", {}).values():
                if child.get("state") != "INSTALLED":
                    continue
                ips = [str(ipaddress.ip_address(ip)) for ip in sa.get("remote-vips", [])]
                reqid = int(child["reqid"])
                if not 0 < reqid < 2**32:
                    continue
                result.append({"token": token, "ike_id": int(sa["uniqueid"]), "reqid": reqid,
                               "public_ip": str(ipaddress.ip_address(sa["remote-host"])),
                               "virtual_ips": ips, "bytes_in": int(child.get("bytes-in", 0)),
                               "bytes_out": int(child.get("bytes-out", 0))})
    return result


def render_rules(store: Store, sessions: list[dict], spec: dict, answers: list,
                 policy: Policy, now: int | None = None) -> str:
    now = int(time.time()) if now is None else now
    pools = [ipaddress.ip_network(spec["pool4"]), ipaddress.ip_network(spec["pool6"])]
    portal = [ipaddress.ip_address(ip) for ip in spec["portal_ips"]]
    denied = [ipaddress.ip_network(net) for net in spec.get("deny_networks", [])]
    allowed: dict[str, int] = {}
    for name, raw_ip, expires in answers:
        ip = ipaddress.ip_address(raw_ip)
        if not ip.is_global or not policy.decide(name, MODE_STRICT).allow:
            continue
        ttl = min(300, int(expires) - now)
        if ttl > 0:
            allowed[str(ip)] = max(allowed.get(str(ip), 0), ttl)
    rules = ["table inet iblocker {"]
    for family, typ in ((4, "ipv4_addr"), (6, "ipv6_addr")):
        rules.append(f"set allowed{family} {{ type {typ}; flags timeout; }}")
        rules.append(f"set unlocked{family} {{ type {typ}; flags timeout; }}")
    rules += ["chain forward { type filter hook forward priority -20; policy accept;"]
    for pool in pools:
        fam = "ip" if pool.version == 4 else "ip6"
        rules += [f"{fam} saddr {pool} jump fromvpn", f"{fam} daddr {pool} jump tovpn"]
    rules += ["}", "chain input { type filter hook input priority -20; policy accept;"]
    for idx, session in enumerate(sessions):
        if store.state(session["token"], now) == "REVOKED":
            continue
        for raw in session["virtual_ips"]:
            ip = ipaddress.ip_address(raw)
            fam = "ip" if ip.version == 4 else "ip6"
            if not any(ip in pool for pool in pools if pool.version == ip.version):
                raise ValueError("VPN address outside configured pools")
            for server in portal:
                if server.version == ip.version:
                    rules += [f"{fam} saddr {ip} {fam} daddr {server} ipsec in reqid {session['reqid']} tcp dport 443 accept"]
    for pool in pools:
        fam = "ip" if pool.version == 4 else "ip6"
        rules += [f"{fam} saddr {pool} drop"]
    rules += ["}", "chain fromvpn {"]
    for pool in pools:
        fam = "ip" if pool.version == 4 else "ip6"
        rules.append(f"{fam} daddr {pool} drop")  # Sin acceso lateral.
    for net in denied:
        fam = "ip" if net.version == 4 else "ip6"
        rules.append(f"{fam} daddr {net} drop")
    for idx, session in enumerate(sessions):
        if store.state(session["token"], now) == "REVOKED":
            continue
        for raw in session["virtual_ips"]:
            ip = ipaddress.ip_address(raw)
            fam = "ip" if ip.version == 4 else "ip6"
            rules.append(f"{fam} saddr {ip} ipsec in reqid {session['reqid']} jump device{idx}")
    rules += ["drop", "}", "chain tovpn {"]
    # Revalidar autorización incluso en conexiones ya establecidas, en ambos sentidos.
    for net in denied:
        fam = "ip" if net.version == 4 else "ip6"
        rules.append(f"{fam} saddr {net} drop")
    for session in sessions:
        if store.state(session["token"], now) == "REVOKED":
            continue
        for raw in session["virtual_ips"]:
            ip = ipaddress.ip_address(raw)
            fam, ver = ("ip", 4) if ip.version == 4 else ("ip6", 6)
            prefix = f"{fam} daddr {ip} ipsec out reqid {session['reqid']} ct state established,related"
            if ver == 4:
                rules.append(f"{prefix} ip protocol icmp icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} accept")
            else:
                rules.append(f"{prefix} meta l4proto ipv6-icmp icmpv6 type {{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem }} accept")
            rules += [f"{prefix} {fam} daddr @unlocked{ver} accept",
                      f"{prefix} {fam} saddr @allowed{ver} accept"]
            for server in portal:
                if server.version == ver:
                    rules.append(f"{prefix} {fam} saddr {server} tcp sport 443 accept")
    rules += ["drop", "}"]
    for idx, session in enumerate(sessions):
        rules += [f"chain device{idx} {{"]
        for ver, fam in ((4, "ip"), (6, "ip6")):
            rules += [f"{fam} saddr @unlocked{ver} accept",
                      f"{fam} daddr @allowed{ver} tcp dport {{ 80, 443, 5223 }} accept",
                      f"{fam} daddr @allowed{ver} udp dport {{ 123, 443 }} accept"]
        for server in portal:
            fam = "ip" if server.version == 4 else "ip6"
            rules.append(f"{fam} daddr {server} tcp dport 443 accept")
        rules += ["drop", "}"]
    # NAT sólo para los pools del servicio; no se borra ninguna otra tabla.
    rules += ["chain nat { type nat hook postrouting priority srcnat; policy accept;"]
    for pool in pools:
        fam = "ip" if pool.version == 4 else "ip6"
        rules.append(f"{fam} saddr {pool} masquerade")
    rules += ["}", "}"]
    for raw, ttl in allowed.items():
        ip = ipaddress.ip_address(raw)
        rules.append(f"add element inet iblocker allowed{ip.version} {{ {ip} timeout {ttl}s }}")
    granted = {}
    for session in sessions:
        device = store.device(session["token"])
        if not device or store.state(session["token"], now) != "UNLOCKED":
            continue
        ttl = min(15, store.effective_until(session["token"]) - now)
        for raw in session["virtual_ips"]:
            ip = ipaddress.ip_address(raw)
            granted[str(ip)] = ttl
    for raw, ttl in granted.items():
        ip = ipaddress.ip_address(raw)
        rules.append(f"add element inet iblocker unlocked{ip.version} {{ {ip} timeout {ttl}s }}")
    return "\n".join(rules) + "\n"


def apply_nft(rules: str):
    found = subprocess.run(["nft", "list", "table", "inet", "iblocker"], capture_output=True, timeout=5)
    batch = ("delete table inet iblocker\n" if found.returncode == 0 else "") + rules
    subprocess.run(["nft", "--check", "-f", "-"], input=batch.encode(), check=True, capture_output=True, timeout=10)
    subprocess.run(["nft", "-f", "-"], input=batch.encode(), check=True, capture_output=True, timeout=10)


def reconcile(config, spec, ca, state, store):
    import vici
    user = pwd.getpwnam("blockservi")
    devices = store.list()
    for device in devices:
        if not device.get("credential_revoked_at"):
            ca.provision(device["token"], config.credentials_dir, user.pw_uid, user.pw_gid)
    ca.crl({d["token"] for d in devices}, {d["token"] for d in devices if d.get("credential_revoked_at")}, spec["crl_file"])
    sock = socket.socket(socket.AF_UNIX)
    sock.settimeout(10)
    sock.connect(spec.get("vici_socket", "/var/run/charon.vici"))
    try:
        session = vici.Session(sock)
        session.load_cert({"type": "X509_CRL", "flag": "NONE", "data": Path(spec["crl_file"]).read_bytes()})
        sessions = sessions_from_vici(list(session.list_sas()))
        by_token: dict[str, set[int]] = {}
        for sa in sessions:
            by_token.setdefault(sa["token"], set()).add(sa["ike_id"])
        duplicates = [token for token, ids in by_token.items() if len(ids) > 1]
        from .profile import load_identity
        invalid = set()
        for sa in sessions:
            try:
                load_identity(config, sa["token"])
            except (FileNotFoundError, ValueError):
                invalid.add(sa["token"])
        blocked = {sa["ike_id"] for sa in sessions if store.state(sa["token"]) == "REVOKED" or sa["token"] in duplicates or sa["token"] in invalid}
        effective = [sa for sa in sessions if sa["ike_id"] not in blocked]
        # Primero cerrar firewall; después terminar SA. Error VICI nunca abre tráfico.
        policy = Policy.load(config.policy_file)
        policy.ensure_allowed([config.portal_host, config.vpn_remote])
        apply_nft(render_rules(store, effective, spec, state.answers(), policy))
        for ike_id in sorted(blocked):
            list(session.terminate({"ike-id": str(ike_id), "timeout": "2000"}))
        state.observe({"healthy": True, "sessions": effective, "duplicates": duplicates,
                       "error": "", "firewall": "applied", "poll_interval_seconds": 5})
    finally:
        sock.close()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--firewall", required=True)
    parser.add_argument("--ca-dir", required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--guard-only", action="store_true")
    args = parser.parse_args(argv)
    config = load(args.config)
    spec = json.loads(Path(args.firewall).read_text())
    if os.geteuid() != 0:
        parser.error("requires root")
    if args.guard_only:
        apply_nft(render_rules(Store(config.state_file), [], spec, [], Policy.load(config.policy_file)))
        return
    with file_lock(os.path.join(args.ca_dir, "controller.lock")):
        state = VirtualState(config.data_dir)
        ca = Authority(args.ca_dir)
        from .licenses import Licenses
        store = Store(config.state_file, Licenses(config.licenses_file))
        # Estado cerrado antes de conectar a VICI. Necesario después de reinicio.
        policy = Policy.load(config.policy_file)
        apply_nft(render_rules(store, [], spec, [], policy))
        while True:
            try:
                reconcile(config, spec, ca, state, store)
            except Exception as exc:
                state.observe({"healthy": False, "sessions": [], "error": type(exc).__name__, "firewall": "error"})
                print(f"IBLOKER controller: {type(exc).__name__}", flush=True)
                # No ocultar errores ni conservar autorizaciones indefinidas.
                try:
                    apply_nft(render_rules(store, [], spec, [], policy))
                except Exception:
                    pass
                if args.once:
                    raise
            if args.once:
                return
            time.sleep(5)


if __name__ == "__main__":
    main()
