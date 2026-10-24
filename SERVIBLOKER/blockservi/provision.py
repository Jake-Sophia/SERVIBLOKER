"""Inicialización explícita de PKI en un VPS preparado; no cambia servicios ni firewall."""
from __future__ import annotations

import argparse
import os
import pwd
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .config import load
from .pki import Authority, private_write
from .virtual import VirtualState


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--ca-dir", default="/var/lib/iblocker-pki")
    parser.add_argument("--swanctl-dir", default="/etc/swanctl")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("requires root")
    config = load(args.config)
    if not config.vpn_enabled or not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", config.vpn_remote):
        parser.error("configure vpn_enabled and a DNS vpn_remote")
    user = pwd.getpwnam("blockservi")
    ca = Authority.initialize(args.ca_dir)
    key, cert = ca.issue(config.vpn_remote, server=True, days=365)
    swan = Path(args.swanctl_dir)
    private_write(swan / "private" / "iblocker-server.key", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private_write(swan / "x509" / "iblocker-server.pem", cert.public_bytes(serialization.Encoding.PEM))
    private_write(swan / "x509ca" / "iblocker-ca.pem", ca.cert.public_bytes(serialization.Encoding.PEM))
    private_write(Path(config.vpn_ca_file), ca.cert.public_bytes(serialization.Encoding.DER))
    os.chown(config.vpn_ca_file, user.pw_uid, user.pw_gid)
    Path(config.credentials_dir).mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(config.credentials_dir, user.pw_uid, user.pw_gid)
    state = VirtualState(config.data_dir)
    os.chown(state.path, user.pw_uid, user.pw_gid)
    crl = swan / "x509crl" / "iblocker.crl"
    crl.parent.mkdir(parents=True, exist_ok=True)
    ca.crl(set(), set(), str(crl))
    print("PKI creada. CA privada sólo root. Falta revisar/cargar swanctl y activar el controlador.")


if __name__ == "__main__":
    main()
