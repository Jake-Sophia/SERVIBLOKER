from __future__ import annotations

import argparse
import base64
import json
import sys
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlencode

from dnslib import DNSRecord, RCODE

RCODES = {0: "RESUELTO", 2: "SERVFAIL", 3: "BLOQUEADO", 5: "RECHAZADO"}

SIEMPRE_PERMITIDO = [
    "youtube.com",
    "m.youtube.com",
    "youtubei.googleapis.com",
    "i.ytimg.com",
    "t.me",
    "telegram.org",
    "web.telegram.org",
    "cdn-telegram.org",
    "captive.apple.com",
    "time.apple.com",
]

SIEMPRE_BLOQUEADO = [
    "itunes.apple.com",
    "secure.itunes.apple.com",
    "xp.apple.com",
    "books.apple.com",
    "phobos.apple.com",
    "gspe35-ssl.ls.apple.com",
    "p01-contactsync.icloud.com",
    "fmzmobile.icloud.com",
    "dns.google",
    "cloudflare-dns.com",
]

SOLO_ESTRICTO = [
    "instagram.com",
    "x.com",
    "tiktok.com",
    "www.netflix.com",
]


def contexto_tls() -> ssl.SSLContext:
    """Certificados de certifi si esta disponible.

    El almacen del Python del sistema no siempre incluye la cadena de
    Let's Encrypt, y un fallo de validacion aqui no dice nada del filtro.
    """
    contexto = ssl.create_default_context()
    try:
        import certifi

        contexto.load_verify_locations(cafile=certifi.where())
    except Exception:
        pass
    return contexto


class Cliente:
    def __init__(self, base: str, host: str, timeout: float = 15.0) -> None:
        self.base = base.rstrip("/")
        self.url = f"{self.base}/dns-query"
        self.host = host
        self.timeout = timeout
        self.tls = contexto_tls()

    def consulta(self, name: str, qtype: str = "A") -> tuple[int, str]:
        wire = DNSRecord.question(name, qtype).pack()
        encoded = base64.urlsafe_b64encode(wire).decode().rstrip("=")
        request = urllib.request.Request(
            f"{self.url}?{urlencode({'dns': encoded})}", headers={"Host": self.host}
        )
        with urllib.request.urlopen(request, timeout=self.timeout, context=self.tls) as response:
            reply = DNSRecord.parse(response.read())
        return int(reply.header.rcode), (str(reply.rr[0].rdata) if reply.rr else "")

    def salud(self) -> dict:
        request = urllib.request.Request(f"{self.base}/salud", headers={"Host": self.host})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.tls) as response:
                return json.loads(response.read())
        except Exception:
            return {}

    def estado(self, token: str, key: str) -> dict:
        request = urllib.request.Request(
            f"{self.base}/api/estado/{token}?k={key}", headers={"Host": self.host}
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.tls) as response:
                cuerpo = response.read()
        except urllib.error.HTTPError as exc:
            return {"error": exc.code, "cuerpo": exc.read()[:200].decode("utf-8", "replace")}
        if not cuerpo:
            return {"error": "respuesta vacia", "status": 200}
        try:
            return json.loads(cuerpo)
        except json.JSONDecodeError:
            return {
                "error": "respuesta no json",
                "status": 200,
                "cuerpo": cuerpo[:200].decode("utf-8", "replace"),
            }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Comprueba el filtro contra un servicio en marcha."
    )
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--token", required=True)
    parser.add_argument(
        "--dominio",
        default="",
        help="dominio para el Host. Si se omite y --url ya es el host del "
        "dispositivo, se usa tal cual. Solo hace falta con --url apuntando a 127.0.0.1.",
    )
    parser.add_argument("--admin-key", default="", help="detecta el modo del dispositivo")
    args = parser.parse_args()

    netloc = args.url.split("//", 1)[-1].split("/")[0].split(":")[0]
    if args.dominio:
        host = f"dev-{args.token}.dns.{args.dominio}"
    elif netloc.startswith(f"dev-{args.token}."):
        host = netloc
    else:
        host = f"dev-{args.token}.dns.ejemplo.com"
    cliente = Cliente(args.url, host)
    fallos = 0

    modo = "strict"
    if args.admin_key:
        estado = cliente.estado(args.token, args.admin_key)
        modo = estado.get("modo", "strict")
        print(f"estado: {json.dumps(estado, ensure_ascii=False)}")
    salud = cliente.salud()
    cautivo = str(salud.get("captive_ip") or "")
    if cautivo:
        print(f"portal cautivo: {cautivo} · pendientes: {salud.get('pendientes', '?')}")
    print(f"consultando {args.url} con Host {host} en modo {modo}\n")

    def comprobar(
        titulo: str, nombres: list[str], esperado: int, apunta_a: str = ""
    ) -> None:
        nonlocal fallos
        print(titulo)
        for name in nombres:
            rcode, rdata = cliente.consulta(name)
            ok = rcode == esperado and (not apunta_a or rdata == apunta_a)
            if not ok:
                fallos += 1
            detalle = f"{RCODES.get(rcode, rcode)} {rdata[:32]}"
            print(f"  {'ok  ' if ok else 'FALLO'} {name:<34} {detalle:<44}")

    comprobar("permitido siempre:", SIEMPRE_PERMITIDO, 0)
    comprobar("bloqueado permanente:", SIEMPRE_BLOQUEADO, int(RCODE.NXDOMAIN))
    if modo == "strict":
        if cautivo:
            comprobar("bloqueado sin codigo (portal cautivo):", SOLO_ESTRICTO, 0, cautivo)
        else:
            comprobar("bloqueado sin codigo:", SOLO_ESTRICTO, int(RCODE.NXDOMAIN))
    else:
        comprobar("permitido con codigo:", SOLO_ESTRICTO, 0)

    print(f"\nfallos: {fallos}")
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
