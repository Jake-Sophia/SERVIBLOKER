"""Emisión local por el controlador root. La web nunca recibe la clave de CA."""
from __future__ import annotations

import base64
import datetime as dt
import os
import secrets
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .persistence import write_json
from .profile import TOKEN_RE


def private_write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


class Authority:
    def __init__(self, directory: str):
        self.directory = Path(directory)
        self.key = serialization.load_pem_private_key((self.directory / "ca.key").read_bytes(), None)
        self.cert = x509.load_pem_x509_certificate((self.directory / "ca.pem").read_bytes())

    @classmethod
    def initialize(cls, directory: str):
        path = Path(directory)
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if any(path.iterdir()):
            raise ValueError("CA directory must be empty; refusing to overwrite")
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        now = dt.datetime.now(dt.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "IBLOKER VPN CA")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                .sign(key, hashes.SHA256()))
        private_write(path / "ca.key", key.private_bytes(serialization.Encoding.PEM,
                      serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        private_write(path / "ca.pem", cert.public_bytes(serialization.Encoding.PEM))
        return cls(directory)

    def issue(self, name: str, *, server: bool = False, days: int = 90):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name[:64])]))
                .issuer_name(self.cert.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(min(now + dt.timedelta(days=days), self.cert.not_valid_after_utc))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server
                                                     else ExtendedKeyUsageOID.CLIENT_AUTH]), False)
                .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), True)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), False)
                .sign(self.key, hashes.SHA256()))
        return key, cert

    def provision(self, token: str, credentials_dir: str, uid: int, gid: int):
        if not TOKEN_RE.fullmatch(token):
            raise ValueError("invalid token")
        target = Path(credentials_dir) / (token + ".json")
        if target.exists():
            return  # Nunca renovar silenciosamente: el perfil offline lleva la identidad anterior.
        key, cert = self.issue(f"{token}.iblocker.invalid")
        cert_path = self.directory / "clients" / (token + ".pem")
        # Puede existir tras una interrupción antes de publicar PKCS12: fallar cerrado.
        private_write(cert_path, cert.public_bytes(serialization.Encoding.PEM))
        password = secrets.token_urlsafe(32)
        bundle = pkcs12.serialize_key_and_certificates(token.encode(), key, cert, [self.cert],
                                                     serialization.BestAvailableEncryption(password.encode()))
        write_json(str(target), {"pkcs12": base64.b64encode(bundle).decode(), "password": password,
                                 "serial": str(cert.serial_number),
                                 "expires_at": int(cert.not_valid_after_utc.timestamp())})
        os.chown(target, uid, gid)

    def crl(self, active_tokens: set[str], revoked_tokens: set[str], output: str):
        now = dt.datetime.now(dt.timezone.utc)
        builder = (x509.CertificateRevocationListBuilder().issuer_name(self.cert.subject)
                   .last_update(now - dt.timedelta(minutes=1)).next_update(now + dt.timedelta(days=1)))
        for path in sorted((self.directory / "clients").glob("*.pem")):
            if path.stem not in active_tokens or path.stem in revoked_tokens:
                cert = x509.load_pem_x509_certificate(path.read_bytes())
                builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder()
                          .serial_number(cert.serial_number).revocation_date(now).build())
        data = builder.sign(self.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
        temp = Path(output + ".tmp")
        temp.write_bytes(data)
        os.replace(temp, output)
