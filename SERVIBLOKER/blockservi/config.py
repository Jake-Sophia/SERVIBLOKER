from __future__ import annotations

import configparser
import os
from dataclasses import dataclass


class ConfigError(Exception):
    pass


def _split(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _valid_ip(value: str) -> str:
    """Valida la IP del portal cautivo para no construir respuestas DNS invalidas."""
    value = value.strip()
    if not value:
        return ""
    parts = value.split(".")
    if len(parts) != 4:
        raise ConfigError(f"general.captive_ip debe ser una IPv4 valida: {value}")
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255 or (len(part) > 1 and part[0] == "0"):
            raise ConfigError(f"general.captive_ip debe ser una IPv4 valida: {value}")
    return value


@dataclass(frozen=True)
class Config:
    path: str
    domain: str
    portal_host: str
    device_dns_suffix: str
    device_prefix: str
    admin_key: str
    data_dir: str
    state_file: str
    licenses_file: str
    policy_file: str
    log_file: str
    log_max_bytes: int
    unlock_hours: int
    doh_path: str
    http_host: str
    http_port: int
    plain_host: str
    plain_port: int
    upstream_doh: tuple[str, ...]
    upstream_udp: tuple[str, ...]
    upstream_timeout: float
    cache_ttl: int
    cache_max: int
    blocked_rcode: str
    captive_ip: str
    request_hours: int
    trust_ip: bool
    vpn_enabled: bool
    vpn_address: str
    vpn_remote: str
    vpn_local_id: str
    vpn_auth_user: str
    vpn_auth_pass: str
    vpn_display: str

    def device_dns_host(self, token: str) -> str:
        return f"{self.device_prefix}{token}.{self.device_dns_suffix}"

    def token_from_dns_host(self, host: str) -> str | None:
        host = host.lower().rstrip(".")
        suffix = "." + self.device_dns_suffix.lower()
        if not host.endswith(suffix):
            return None
        label = host[: -len(suffix)]
        prefix = self.device_prefix
        if not label.startswith(prefix) or len(label) == len(prefix):
            return None
        return label[len(prefix):]

    def portal_origin(self) -> str:
        return f"https://{self.portal_host}"

    def shared_doh_url(self) -> str:
        """URL unica de DoH que comparten todos los telefonos."""
        return f"https://{self.portal_host}{self.doh_path}"

    def activation_url(self, token: str) -> str:
        return f"{self.portal_origin()}/activar/{token}"


def load(path: str) -> Config:
    if not os.path.isfile(path):
        raise ConfigError(f"No existe el fichero de configuración: {path}")

    parser = configparser.ConfigParser()
    with open(path, "r", encoding="utf-8") as handle:
        parser.read_file(handle)

    def get(section: str, option: str, fallback: str | None = None) -> str:
        if parser.has_option(section, option):
            return parser.get(section, option).strip()
        if fallback is not None:
            return fallback
        raise ConfigError(f"Falta {section}.{option} en {path}")

    def get_int(section: str, option: str, fallback: int) -> int:
        raw = get(section, option, str(fallback))
        try:
            return int(raw)
        except ValueError as exc:
            raise ConfigError(f"{section}.{option} debe ser un entero: {raw}") from exc

    def get_float(section: str, option: str, fallback: float) -> float:
        raw = get(section, option, str(fallback))
        try:
            return float(raw)
        except ValueError as exc:
            raise ConfigError(f"{section}.{option} debe ser un número: {raw}") from exc

    def get_bool(section: str, option: str, fallback: bool) -> bool:
        raw = get(section, option, "1" if fallback else "0").lower()
        if raw in ("1", "true", "yes", "si", "sí", "on"):
            return True
        if raw in ("0", "false", "no", "off"):
            return False
        raise ConfigError(f"{section}.{option} debe ser booleano: {raw}")

    domain = get("general", "domain").lower().rstrip(".")
    device_dns_suffix = get("general", "device_dns_suffix", f"dns.{domain}").lower().rstrip(".")
    data_dir = get("general", "data_dir", "/var/lib/blockservi")
    config = Config(
        path=os.path.abspath(path),
        domain=domain,
        portal_host=get("general", "portal_host", f"app.{domain}").lower(),
        device_dns_suffix=device_dns_suffix,
        device_prefix=get("general", "device_prefix", "dev-"),
        admin_key=get("general", "admin_key"),
        data_dir=data_dir,
        state_file=get("general", "state_file", os.path.join(data_dir, "devices.json")),
        licenses_file=get("general", "licenses_file", os.path.join(data_dir, "licenses.json")),
        policy_file=get("general", "policy_file", os.path.join(data_dir, "policy.json")),
        log_file=get("general", "log_file", os.path.join(data_dir, "blocked.log")),
        log_max_bytes=get_int("general", "log_max_bytes", 8 * 1024 * 1024),
        unlock_hours=get_int("general", "unlock_hours", 24),
        doh_path=get("general", "doh_path", "/dns-query"),
        http_host=get("network", "http_host", "127.0.0.1"),
        http_port=get_int("network", "http_port", 8080),
        plain_host=get("network", "plain_host", "127.0.0.1"),
        plain_port=get_int("network", "plain_port", 5353),
        upstream_doh=_split(get("upstream", "doh", "https://1.1.1.1/dns-query,https://dns.google/dns-query")),
        upstream_udp=_split(get("upstream", "udp", "")),
        upstream_timeout=get_float("upstream", "timeout", 5.0),
        cache_ttl=get_int("upstream", "cache_ttl", 300),
        cache_max=get_int("upstream", "cache_max", 20000),
        vpn_enabled=get_bool("vpn", "vpn_enabled", False),
        vpn_address=get("vpn", "vpn_address", get("vpn", "vpn_remote", "")),
        vpn_remote=get("vpn", "vpn_remote", ""),
        vpn_local_id=get("vpn", "vpn_local_id", "wifi"),
        vpn_auth_user=get("vpn", "vpn_auth_user", ""),
        vpn_auth_pass=get("vpn", "vpn_auth_pass", ""),
        vpn_display=get("vpn", "vpn_display", "Acceso de la empresa"),
        blocked_rcode=get("general", "blocked_rcode", "nxdomain"),
        captive_ip=_valid_ip(get("general", "captive_ip", "")),
        request_hours=get_int("general", "request_hours", 24),
        # Con un unico perfil para todos los telefonos no hay token en el Host,
        # asi que el equipo se identifica por su IP. Ponerlo a 0 obliga a usar
        # un perfil por equipo, con su host y su token.
        trust_ip=get_bool("general", "trust_ip", True),
    )

    if config.admin_key == "" or config.admin_key == "cambia-esta-clave":
        raise ConfigError("general.admin_key debe cambiarse antes de arrancar")
    if not config.domain:
        raise ConfigError("general.domain no puede estar vacío")
    return config
