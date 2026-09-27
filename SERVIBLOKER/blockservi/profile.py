from __future__ import annotations

import plistlib
from typing import Any

from .config import Config


def build_profile(
    config: Config,
    token: str,
    organization: str = "BloqueoServi",
    doh_url: str | None = None,
) -> bytes:
    # Con doh_url=None cada equipo usa su propio host (dev-<token>.dns...).
    # Pasandolo, todos comparten la misma URL: es lo que permite instalar un
    # unico perfil en cualquier telefono, porque el equipo se reconoce por su IP.
    url = doh_url or f"https://{config.device_dns_host(token)}{config.doh_path}"
    contenido: list[dict[str, Any]] = [
        {
            "DNSSettings": {
                "DNSServerURLs": [url],
                "MatchDomains": [],
                "SearchDomains": [],
            },
            "PayloadDescription": "Resolucion DNS cifrada con filtrado de acceso",
            "PayloadDisplayName": "Filtrado de acceso",
            "PayloadIdentifier": f"com.bloqueoservi.dns.{token}",
            "PayloadType": "com.apple.dnsSettings.managed",
            "PayloadUUID": _uuid(f"com.bloqueoservi.dns.{token}.settings"),
            "PayloadVersion": 1,
        },
        {
            # Asi abre iOS el portal por su cuenta. El movil comprueba una URL de
            # prueba; si no llega a la pagina de exito da la red por captiva y
            # abre este portal, que es la pagina del codigo. Por eso
            # captive.apple.com esta bloqueado: si se le dejara pasar, la
            # comprobacion diria que todo va bien y el portal no apareceria.
            "PayloadDescription": "Abre la pantalla del codigo al detectar la red",
            "PayloadDisplayName": "Portal de activacion",
            "PayloadIdentifier": f"com.bloqueoservi.captive.{token}",
            "PayloadType": "com.apple.captive-network-support",
            "PayloadUUID": _uuid(f"com.bloqueoservi.captive.{token}"),
            "PayloadVersion": 1,
            "PortalURL": f"https://{config.portal_host}/activar",
            "SupportedURLs": ["http://captive.apple.com/hotspot-detect.html"],
        },
    ]
    if config.vpn_enabled:
        contenido.append(_vpn_payload(config, token))
    payload: dict[str, Any] = {
        "PayloadContent": contenido,
        "PayloadDescription": (
            "Instala la resolucion DNS cifrada del servicio. "
            "No se solicita ninguna contrasena, PIN ni dato biometrico."
        ),
        "PayloadDisplayName": "Servicio de acceso",
        "PayloadIdentifier": f"com.bloqueoservi.dns.{token}",
        "PayloadOrganization": organization,
        "PayloadScope": "System",
        "PayloadType": "Configuration",
        "PayloadUUID": _uuid(f"com.bloqueoservi.dns.{token}.root"),
        "PayloadVersion": 1,
    }
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML)


def _vpn_payload(config: Config, token: str) -> dict[str, Any]:
    """Tunel IKEv2 que manda todo el trafico por el servidor.

    Sin esto el filtrado es solo de nombres: el movil entra a la red del sitio
    donde este y pregunta al DNS del perfil, pero cualquier app con su propio
    resolver se escapa. Con VPNSendAllTraffic todo el trafico pasa por el
    servidor, y ahi ya no hay forma de salir sin que el filtro lo vea.

    Durante la validacion se deja como VPN manual: si no llega ni un paquete al
    servidor, el problema esta antes de IKEv2 (perfil, DNS, red o iOS). Cuando
    conecte bien, se puede volver a activar OnDemand.
    """
    ike: dict[str, Any] = {
        "RemoteAddress": config.vpn_address,
        "RemoteIdentifier": config.vpn_remote,
        "LocalIdentifier": config.vpn_local_id,
        # Con servidor de certificados publico (Let's Encrypt) no hace falta
        # embeber la CA: el movil lo valida solo.
        "AuthenticationMethod": "None",
        "ExtendedAuthEnabled": 1,
        "AuthName": config.vpn_auth_user,
        "AuthPassword": config.vpn_auth_pass,
        "DeadPeerDetectionRate": "High",
        "DisableMOBIKE": 0,
        "NATKeepAliveInterval": 20,
    }
    return {
        "PayloadDescription": "Envia todo el trafico al servidor de la empresa",
        "PayloadDisplayName": config.vpn_display,
        "PayloadIdentifier": f"com.bloqueoservi.vpn.{token}",
        "PayloadType": "com.apple.vpn.managed",
        "PayloadUUID": _uuid(f"com.bloqueoservi.vpn.{token}"),
        "PayloadVersion": 1,
        "UserDefinedName": config.vpn_display,
        "VPNType": "IKEv2",
        "VPNSendAllTraffic": True,
        "DisconnectOnSleep": False,
        "IncludeAllNetworks": True,
        "ExcludeLocalNetworks": False,
        "OnDemandEnabled": 1,
        "OnDemandUserOverrideDisabled": True,
        "OnDemandRules": [
            {"Action": "Connect", "InterfaceTypeMatch": "WiFi"},
            {"Action": "Connect", "InterfaceTypeMatch": "Cellular"},
        ],
        "IKEv2": ike,
    }


def build_vpn_test_profile(config: Config) -> bytes:
    """Perfil de diagnostico: solo VPN IKEv2, sin DNS ni portal.

    Replica la forma del perfil VPN antiguo que ya existia en el VPS. Sirve para
    separar dos problemas: si este perfil tampoco inicia IKEv2, el fallo no esta
    en blockservi ni en el DNS, sino en iOS/red/servidor VPN.
    """
    vpn = _vpn_payload(config, "test")
    vpn.update(
        {
            "PayloadIdentifier": "com.wifi.access.ikev2",
            "PayloadDisplayName": "WiFi Access",
            "PayloadUUID": _uuid("com.wifi.access.ikev2"),
            "UserDefinedName": "WiFi Access",
            "OnDemandEnabled": 1,
            "OnDemandRules": [
                {"Action": "Connect", "InterfaceTypeMatch": "WiFi"},
                {"Action": "Connect", "InterfaceTypeMatch": "Cellular"},
            ],
        }
    )
    payload: dict[str, Any] = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": "com.wifi.access",
        "PayloadUUID": _uuid("com.wifi.access.root"),
        "PayloadDisplayName": "WiFi Access",
        "PayloadDescription": "WiFi Access VPN",
        "PayloadOrganization": "WiFi",
        "PayloadScope": "System",
        "PayloadContent": [vpn],
    }
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML)


def _uuid(seed: str) -> str:
    import uuid

    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"bloqueoservi:{seed}"))
