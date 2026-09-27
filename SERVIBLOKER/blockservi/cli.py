from __future__ import annotations

import argparse
import asyncio
import os
import signal
import ssl
import sys
import time

import aiohttp
import certifi
from aiohttp import web

from . import __version__
from .apikeys import SCOPES, ApiKeys
from .codes import Codes
from .config import Config, ConfigError, load as load_config
from .dnsfilter import Filter
from .licenses import Licenses
from .plain import PlainBridge
from .querylog import QueryLog
from .rules import MODE_STRICT, MODE_UNLOCKED, Policy
from .store import Store
from .upstream import Upstream
from .web import Service

DEFAULT_CONFIG = os.environ.get("BLOCKSERVI_CONFIG", "blockservi.ini")


class Components:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.policy = Policy.load(config.policy_file)
        self.policy.ensure_allowed(
            [config.portal_host, config.device_dns_suffix, config.domain]
        )
        self.store = Store(config.state_file)
        self.licenses = Licenses(config.licenses_file)
        self.codes = Codes(os.path.join(config.data_dir, 'codes.json'))
        self.api_keys = ApiKeys(os.path.join(config.data_dir, 'api_keys.json'))
        self.log = QueryLog(config.log_file, config.log_max_bytes)
        self.upstream = Upstream(
            config.upstream_doh,
            config.upstream_udp,
            timeout=config.upstream_timeout,
            cache_ttl=config.cache_ttl,
            cache_max=config.cache_max,
        )
        self.filter = Filter(
            self.policy,
            self.store,
            self.upstream,
            self.log,
            blocked_rcode=config.blocked_rcode,
            captive_ip=config.captive_ip,
        )
        self.service = Service(
            config, self.filter, self.store, self.licenses, self.codes, self.api_keys
        )


async def serve(config: Config) -> None:
    parts = Components(config)
    session = aiohttp.ClientSession(
        headers={"User-Agent": f"bloqueoservi/{__version__}"},
        connector=aiohttp.TCPConnector(
            limit=64,
            ttl_dns_cache=300,
            ssl=ssl.create_default_context(cafile=certifi.where()),
        ),
    )
    parts.upstream.set_session(session)

    app = parts.service.build_app()
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, config.http_host, config.http_port).start()

    device_map: dict[str, str] = {}
    loop = asyncio.get_running_loop()
    bridge = PlainBridge(loop, parts.filter, device_map, config.upstream_timeout)
    plain_servers = bridge.start(config.plain_host, config.plain_port)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signal_name in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signal_name, stop.set)
        except NotImplementedError:
            pass

    print(f"bloqueoservi {__version__} en marcha", flush=True)
    doh = f"http://{config.http_host}:{config.http_port}{config.doh_path}"
    print(f"  DoH en {doh}", flush=True)
    plain = f"{config.plain_host}:{config.plain_port}"
    print(f"  DNS en claro en {plain} (udp y tcp)", flush=True)
    print(f"  Portal: {config.portal_origin()}/activar", flush=True)
    if config.captive_ip:
        print(f"  Portal cautivo: lo bloqueado resuelve a {config.captive_ip}", flush=True)
    print(f"  Panel: {config.portal_origin()}/panel", flush=True)
    print(f"  Politica: {config.policy_file}", flush=True)
    devices = len(parts.store.list())
    print(f"  Dispositivos: {devices} | licencias: {parts.licenses.count()}", flush=True)

    await stop.wait()

    for server in plain_servers:
        server.stop()
    await runner.cleanup()
    await session.close()
    parts.store.flush()
    print("bloqueoservi detenido", flush=True)


def cmd_serve(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    try:
        asyncio.run(serve(config))
    except KeyboardInterrupt:
        return 0
    return 0


def cmd_caddy(args: argparse.Namespace, store: Store | None = None) -> int:
    """Escribe un bloque de Caddy por dispositivo.

    El comodin *.dns.<dominio> no vale: Let's Encrypt solo ofrece dns-01 para
    comodines, que exigiria un API token de Cloudflare. En su lugar cada
    dispositivo recibe un host explicito, que si se puede pedir por HTTP-01 sin
    tocar credenciales. El Caddyfile principal hace import de este directorio.
    """
    config = load_config(args.config)
    store = store or Store(config.state_file)
    devices = store.list()
    if not devices:
        print("No hay dispositivos registrados.")
        return 0

    destino = args.caddy_dir
    if destino:
        os.makedirs(destino, exist_ok=True)
        for viejo in os.listdir(destino):
            if viejo.endswith(".caddy"):
                os.remove(os.path.join(destino, viejo))

    for device in devices:
        token = device["token"]
        host = config.device_dns_host(token)
        bloque = (
            f"# {device.get('label') or 'sin etiqueta'} - {token}\n"
            f"{host} {{\n"
            f"\treverse_proxy 127.0.0.1:{config.http_port} {{\n"
            f"\t\theader_up Host {{host}}\n"
            f"\t}}\n"
            f"}}\n"
        )
        if destino:
            with open(os.path.join(destino, f"{token}.caddy"), "w", encoding="utf-8") as fh:
                fh.write(bloque)
            print(f"escrito {destino}/{token}.caddy  ({host})")
        else:
            print(bloque)
    print(f"{len(devices)} dispositivo(s). Recarga Caddy para pedir los certificados.")
    return 0


def cmd_device(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    store = Store(config.state_file)

    if args.accion == "add":
        device = store.add(args.label or "", args.code or "")
        token = device["token"]
        print(f"token: {token}")
        print(f"etiqueta: {device['label'] or '(sin etiqueta)'}")
        print(f"DNS: {config.device_dns_host(token)}")
        print(f"activacion: {config.activation_url(token)}")
        print(f"perfil: {config.portal_origin()}/perfil/{token}.mobileconfig?k=CLAVE")
        if args.caddy_dir:
            cmd_caddy(args, store=store)
        return 0

    if args.accion == "caddy":
        return cmd_caddy(args, store=store)

    if args.accion == "list":
        devices = store.list()
        if not devices:
            print("No hay dispositivos registrados.")
            return 0
        now = int(time.time())
        for device in devices:
            remaining = int(device.get("unlocked_until", 0)) - now
            state = f"libre {remaining // 3600}h" if remaining > 0 else "restringido"
            seen = device.get("last_seen") or 0
            seen_text = time.strftime("%d/%m %H:%M", time.localtime(seen)) if seen else "nunca"
            print(
                f"{device['token']}  {device.get('label') or '(sin etiqueta)':<24} "
                f"{state:<12} vistos:{seen_text}  usados:{device.get('unlock_count', 0)}"
            )
        return 0

    token = (args.token or "").strip().lower()
    if not token:
        print("Falta el token del dispositivo", file=sys.stderr)
        return 2
    device = store.device(token)
    if device is None:
        print(f"Dispositivo desconocido: {token}", file=sys.stderr)
        return 2

    if args.accion == "unlock":
        hours = args.hours or config.unlock_hours
        updated = store.unlock(token, args.code or device.get("code", ""), hours)
        until = int(updated["unlocked_until"])
        momento = time.strftime("%d/%m/%Y %H:%M", time.localtime(until))
        print(f"{token}: acceso completo hasta {momento}")
        return 0

    if args.accion == "lock":
        store.set_unlocked_until(token, 0)
        print(f"{token}: vuelve al modo restringido")
        return 0

    if args.accion == "delete":
        store.delete(token)
        print(f"{token}: eliminado")
        return 0

    return 2


def cmd_profile(args: argparse.Namespace) -> int:
    from .profile import build_profile

    config = load_config(args.config)
    store = Store(config.state_file)
    token = args.token.strip().lower()
    if store.device(token) is None:
        print(f"Dispositivo desconocido: {token}", file=sys.stderr)
        return 2
    data = build_profile(config, token)
    if args.output:
        with open(args.output, "wb") as handle:
            handle.write(data)
        print(f"Perfil escrito en {args.output}")
        print("Instalacion en el iPhone: abre el fichero en Safari y pulsa Instalar.")
    else:
        sys.stdout.buffer.write(data)
    return 0


def cmd_decide(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    parts = Components(config)
    for name in args.dominio:
        for mode in (MODE_STRICT, MODE_UNLOCKED):
            decision = parts.policy.decide(name, mode)
            mark = "PERMITIDO" if decision.allow else "BLOQUEADO"
            print(f"{mark:<10} {mode:<10} {name:<40} {decision.reason}")
        print()
    return 0


def cmd_log(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    log = QueryLog(config.log_file, config.log_max_bytes)
    entries = log.tail_file(args.numero)
    if not entries:
        print("No hay consultas registradas todavia.")
        return 0
    for entry in entries:
        stamp = time.strftime("%d/%m %H:%M:%S", time.localtime(int(entry.get("at", 0))))
        device = (entry.get("device") or "-")[:12]
        name = entry.get("name", "")
        mode = entry.get("mode", "")
        reason = entry.get("reason", "")
        print(f"{stamp}  {device:<12} {mode:<9} {name:<45} {reason}")
    return 0


def cmd_apikey(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    keys = ApiKeys(os.path.join(config.data_dir, "api_keys.json"))

    if args.accion == "create":
        try:
            entry, key = keys.create(args.scope, args.note)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print("API key (solo se ve ahora, guardala en tu servidor):")
        print(f"  {key}")
        print(f"id: {entry['id']}  permiso: {entry['scope']}  usos: 0")
        return 0

    if args.accion == "list":
        entradas = keys.list()
        if not entradas:
            print("No hay API keys.")
            return 0
        for e in entradas:
            estado = "REVOCADA" if e.get("revocado") else "activa"
            visto = e.get("last_used_at") or 0
            texto = (
                time.strftime("%d/%m %H:%M", time.localtime(visto)) if visto else "nunca"
            )
            print(
                f"{e['id']}  {e['scope']:<10} {estado:<8} usos:{e.get('uses', 0):<5} "
                f"ultimo:{texto}  {e.get('note', '')}"
            )
        return 0

    if args.accion == "revoke":
        if keys.revoke(args.id):
            print(f"API key revocada: {args.id}")
            return 0
        print(f"No hay ninguna API key con id {args.id}", file=sys.stderr)
        return 2

    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blockservi",
        description="Filtro de acceso DNS para iPhone con activacion por codigo.",
    )
    parser.add_argument(
        "--config", default=DEFAULT_CONFIG, help="ruta del fichero de configuracion"
    )
    parser.add_argument("--version", action="version", version=f"blockservi {__version__}")
    sub = parser.add_subparsers(dest="comando", required=True)

    serve_parser = sub.add_parser("serve", help="arranca el servicio")
    serve_parser.set_defaults(func=cmd_serve)

    device_parser = sub.add_parser("device", help="gestiona dispositivos")
    device_sub = device_parser.add_subparsers(dest="accion", required=True)

    add_parser = device_sub.add_parser("add", help="registra un dispositivo")
    add_parser.add_argument("--label", default="", help="nombre del equipo")
    add_parser.add_argument("--code", default="", help="codigo de licencia a associar")
    add_parser.add_argument(
        "--caddy-dir",
        default="",
        help="escribe ahi los bloques de Caddy y recarga (p. ej. /etc/caddy/dispositivos)",
    )
    add_parser.set_defaults(func=cmd_device)

    caddy_parser = device_sub.add_parser(
        "caddy", help="genera los hosts de Caddy, uno por dispositivo"
    )
    caddy_parser.add_argument("--caddy-dir", default="", help="directorio destino")
    caddy_parser.set_defaults(func=cmd_device)

    list_parser = device_sub.add_parser("list", help="lista los dispositivos")
    list_parser.set_defaults(func=cmd_device)

    unlock_parser = device_sub.add_parser("unlock", help="habilita acceso completo")
    unlock_parser.add_argument("token")
    unlock_parser.add_argument("--hours", type=int, default=0, help="0 usa unlock_hours")
    unlock_parser.add_argument("--code", default="")
    unlock_parser.set_defaults(func=cmd_device)

    lock_parser = device_sub.add_parser("lock", help="vuelve al modo restringido")
    lock_parser.add_argument("token")
    lock_parser.set_defaults(func=cmd_device)

    delete_parser = device_sub.add_parser("delete", help="elimina un dispositivo")
    delete_parser.add_argument("token")
    delete_parser.set_defaults(func=cmd_device)

    profile_parser = sub.add_parser("profile", help="genera el perfil para instalar en el iPhone")
    profile_parser.add_argument("token")
    profile_parser.add_argument("-o", "--output", default="")
    profile_parser.set_defaults(func=cmd_profile)

    decide_parser = sub.add_parser("decide", help="consulta como se resuelve un dominio")
    decide_parser.add_argument("dominio", nargs="+")
    decide_parser.set_defaults(func=cmd_decide)

    log_parser = sub.add_parser("log", help="muestra las consultas bloqueadas")
    log_parser.add_argument("-n", "--numero", type=int, default=40)
    log_parser.set_defaults(func=cmd_log)

    apikey_parser = sub.add_parser("apikey", help="claves para que otro servidor active codigos")
    apikey_sub = apikey_parser.add_subparsers(dest="accion", required=True)

    apikey_create = apikey_sub.add_parser("create", help="crea una API key")
    apikey_create.add_argument(
        "--scope", default="activar", choices=(*SCOPES, "*"), help="permiso de la clave"
    )
    apikey_create.add_argument("--note", default="", help="para que se usa")
    apikey_create.set_defaults(func=cmd_apikey)

    apikey_list = apikey_sub.add_parser("list", help="lista las API keys")
    apikey_list.set_defaults(func=cmd_apikey)

    apikey_revoke = apikey_sub.add_parser("revoke", help="revoca una API key")
    apikey_revoke.add_argument("id")
    apikey_revoke.set_defaults(func=cmd_apikey)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"error de configuracion: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
