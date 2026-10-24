"""Perfiles autocontenidos. Ningún payload de inscripción remota/SCEP."""
from __future__ import annotations

import base64
import json
import os
import plistlib
import re
import time
import uuid
from typing import Any

from .config import Config

TOKEN_RE = re.compile(r"^[a-f0-9]{12,48}$")


def _uuid(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"iblocker:{seed}"))


def load_identity(config: Config, token: str, *, allow_expired: bool = False) -> dict:
    if not TOKEN_RE.fullmatch(token):
        raise ValueError("token_invalido")
    path = os.path.join(config.credentials_dir, token + ".json")
    with open(path, encoding="utf-8") as stream:
        identity = json.load(stream)
    if not allow_expired and int(identity["expires_at"]) <= time.time():
        raise ValueError("certificado_vencido")
    return identity


def _payload(kind: str, token: str, name: str, **values) -> dict:
    return {"PayloadType": kind, "PayloadVersion": 1,
            "PayloadIdentifier": f"com.iblocker.{name}.{token}",
            "PayloadUUID": _uuid(f"{name}:{token}"),
            "PayloadDisplayName": f"IBLOKER {name}", **values}


def build_profile(config: Config, token: str, organization: str = "IBLOKER",
                  doh_url: str | None = None, *, profile_uuid: str | None = None,
                  identity: dict | None = None, wifi: dict | None = None) -> bytes:
    if not TOKEN_RE.fullmatch(token) and token != "todos":
        raise ValueError("token_invalido")
    # Un solo TLS para el portal. Los hosts individuales antiguos siguen atendidos.
    url = doh_url or f"{config.portal_origin()}{config.doh_path}/{token}"
    if not url.startswith("https://"):
        raise ValueError("DoH requiere HTTPS")
    content = [_payload("com.apple.dnsSettings.managed", token, "DNS",
                        DNSSettings={"DNSProtocol": "HTTPS", "ServerURL": url,
                                     **({"ServerAddresses": list(config.doh_server_addresses)} if config.doh_server_addresses else {})})]
    if config.vpn_enabled:
        if token == "todos":
            raise ValueError("VPN requiere perfil individual")
        identity = identity or load_identity(config, token)
        content.append(_payload("com.apple.security.pkcs12", token, "identidad",
                                PayloadContent=base64.b64decode(identity["pkcs12"]),
                                Password=identity["password"]))
        with open(config.vpn_ca_file, "rb") as stream:
            content.append(_payload("com.apple.security.root", token, "CA",
                                    PayloadContent=stream.read()))
        vpn = _vpn_payload(config, token)
        vpn["DNS"] = {"DNSProtocol": "HTTPS", "ServerURL": url, "ServerAddresses": list(config.doh_server_addresses)}
        content.append(vpn)
    if wifi:
        ssid = str(wifi.get("ssid", ""))
        security = wifi.get("security", "WPA2")
        if not 1 <= len(ssid.encode()) <= 32 or security not in ("None", "WPA2", "WPA3"):
            raise ValueError("wifi_invalido")
        values: dict[str, Any] = {"SSID_STR": ssid, "EncryptionType": security,
                                 "AutoJoin": bool(wifi.get("auto_join", True))}
        if security != "None":
            password = str(wifi.get("password", ""))
            if not 8 <= len(password) <= 63:
                raise ValueError("wifi_password_invalido")
            values["Password"] = password
        content.append(_payload("com.apple.wifi.managed", token, "WiFi", **values))
    payload = _payload("Configuration", token, "perfil", PayloadContent=content,
                       PayloadOrganization=organization, PayloadScope="System",
                       PayloadDescription="Perfil individual de acceso IBLOKER. Removible por el usuario.")
    if len(token) == 12 and not profile_uuid:
        # Identidad raíz del generador anterior: reinstalar sustituye el mismo perfil.
        payload["PayloadIdentifier"] = f"com.bloqueoservi.dns.{token}"
        payload["PayloadUUID"] = str(uuid.uuid5(uuid.NAMESPACE_URL,
                                    f"bloqueoservi:com.bloqueoservi.dns.{token}.root"))
    if profile_uuid:
        payload["PayloadUUID"] = str(uuid.UUID(profile_uuid))
    payload["PayloadDisplayName"] = "IBLOKER"
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML)


def _vpn_payload(config: Config, token: str) -> dict:
    if not config.vpn_address or not config.vpn_remote:
        raise ValueError("vpn_servidor_incompleto")
    return _payload("com.apple.vpn.managed", token, "VPN",
                    UserDefinedName="IBLOKER", VPNType="IKEv2",
                    IKEv2={"RemoteAddress": config.vpn_address,
                           "RemoteIdentifier": config.vpn_remote,
                           "OnDemandEnabled": 1, "OnDemandRules": [{"Action": "Connect"}],
                           "IncludeAllNetworks": 1, "ExcludeLocalNetworks": 0,
                           "LocalIdentifier": f"{token}.iblocker.invalid",
                           "AuthenticationMethod": "Certificate", "ExtendedAuthEnabled": 0,
                           "PayloadCertificateUUID": _uuid(f"identidad:{token}"),
                           "DeadPeerDetectionRate": "High", "DisableMOBIKE": 0})


def build_vpn_test_profile(config: Config) -> bytes:
    raise ValueError("Diagnóstico compartido retirado: use un perfil individual con certificado")
