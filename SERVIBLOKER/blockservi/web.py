from __future__ import annotations

import asyncio
import hmac
import os
import secrets
import subprocess
import time
from collections import defaultdict, deque
from typing import Any

from aiohttp import web

from .apikeys import SCOPE_ACTIVAR, SCOPE_CONSULTAR, SCOPE_REVOCAR, ApiKeys
from .codes import Codes
from .config import Config
from .dnsfilter import Filter
from .licenses import Licenses
from .portal import admin_page, device_page, manual_page
from .profile import build_profile, build_vpn_test_profile
from .rules import MODE_STRICT, MODE_UNLOCKED
from .store import Store

DOH_CONTENT_TYPE = "application/dns-message"
MAX_ATTEMPTS = 5
ATTEMPT_WINDOW = 900
LOCKOUT_SECONDS = 1800


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


class RateLimiter:
    def __init__(self) -> None:
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._locked: dict[str, float] = {}

    def check(self, key: str) -> int:
        now = time.time()
        locked_until = self._locked.get(key, 0.0)
        if locked_until > now:
            return int(locked_until - now)
        window = self._attempts[key]
        while window and now - window[0] > ATTEMPT_WINDOW:
            window.popleft()
        return 0

    def fail(self, key: str) -> None:
        self._attempts[key].append(time.time())
        if len(self._attempts[key]) >= MAX_ATTEMPTS:
            self._locked[key] = time.time() + LOCKOUT_SECONDS
            self._attempts[key].clear()

    def success(self, key: str) -> None:
        self._attempts.pop(key, None)
        self._locked.pop(key, None)


def admin_required(handler):
    """Exige la clave de administracion por cabecera X-Admin-Key o por ?k=."""

    async def wrapper(request: web.Request) -> web.StreamResponse:
        service: "Service" = request.app["service"]
        config = service.config
        provided = request.query.get("k") or request.headers.get("X-Admin-Key") or ""
        if not provided or not hmac.compare_digest(provided, config.admin_key):
            return web.json_response({"error": "no_autorizado"}, status=401)
        return await handler(service, request)

    wrapper.__name__ = getattr(handler, "__name__", "handler")
    return staticmethod(wrapper)


def api_key_required(scope: str):
    """Exige una API key con ese permiso, solo por cabecera.

    A proposito no se acepta en la query: ahi la clave se quedaria escrita en
    los registros de acceso de Caddy y en el historial del navegador.
    """

    def envoltura(handler):
        async def wrapper(request: web.Request) -> web.StreamResponse:
            service: "Service" = request.app["service"]
            key = request.headers.get("X-API-Key", "")
            if not key:
                return web.json_response(
                    {"error": "falta_api_key", "detalle": "envia la cabecera X-API-Key"},
                    status=401,
                )
            entry = await asyncio.to_thread(service.api_keys.verify, key, scope)
            if entry is None:
                return web.json_response({"error": "api_key_invalida"}, status=403)
            request["api_key"] = entry
            return await handler(service, request)

        wrapper.__name__ = getattr(handler, "__name__", "handler")
        return staticmethod(wrapper)

    return envoltura


class Service:
    def __init__(
        self,
        config: Config,
        dns_filter: Filter,
        store: Store,
        licenses: Licenses,
        codes: Codes,
        api_keys: "ApiKeys | None" = None,
        organization: str = "BloqueoServi",
    ) -> None:
        self.config = config
        self.filter = dns_filter
        self.store = store
        self.licenses = licenses
        self.codes = codes
        self.api_keys = api_keys
        self.organization = organization
        self.limiter = RateLimiter()
        self.started_at = time.time()

    def _peer_ip(self, request: web.Request) -> str:
        """IP real del cliente.

        Caddy conecta desde 127.0.0.1 y deja la direccion del movil en
        X-Forwarded-For. Solo se acepta esa cabecera si el peer es local, que
        es el unico caso en que el servicio no esta expuesto directamente.

        Con el perfil unico esta IP es la identidad del telefono, asi que no
        puede falsearse. Si hay Cloudflare delante se usa CF-Connecting-IP, que
        Cloudflare sobrescribe siempre con la direccion que ve; en cambio el
        X-Forwarded-For lo puede mandar el cliente. De XFF se toma la primera
        entrada, que es la que pone el proxy mas cercano al cliente, nunca las
        que van detras.
        """
        remote = request.remote or ""
        connecting = request.headers.get("CF-Connecting-IP", "").strip()
        if connecting:
            return connecting
        if remote.startswith("127.") or remote in ("::1", "localhost"):
            forwarded = request.headers.get("X-Forwarded-For", "")
            for candidate in forwarded.split(","):
                candidate = candidate.strip()
                if candidate:
                    return candidate
        return remote

    def _token_from_request(self, request: web.Request) -> str | None:
        host = (request.headers.get("Host") or "").split(":")[0]
        return self.config.token_from_dns_host(host)

    def _authorized(self, request: web.Request) -> bool:
        provided = request.query.get("k") or request.headers.get("X-Admin-Key") or ""
        return bool(provided) and hmac.compare_digest(provided, self.config.admin_key)

    def _sync_tunnel_firewall(self) -> None:
        for cmd in (
            "/usr/local/sbin/blockservi-sync-unlocked",
            "/usr/local/sbin/blockservi-sync-unlocked6",
            "/usr/local/sbin/blockservi-tunelorder",
        ):
            if not os.path.exists(cmd):
                continue
            run_cmd = [cmd] if os.geteuid() == 0 else ["sudo", "-n", cmd]
            subprocess.run(run_cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    async def handle_doh(self, request: web.Request) -> web.StreamResponse:
        if request.method == "GET":
            raw = request.query.get("dns", "")
            import base64

            try:
                wire = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
            except Exception:
                return web.Response(status=400, text="dns mal codificado")
        elif request.method == "POST":
            wire = await request.read()
        else:
            return web.Response(status=405, headers={"Allow": "GET, POST"})

        if not wire:
            return web.Response(status=400, text="consulta vacia")

        # El token sale del Host (dev-<token>.dns...). Nunca se deduce por IP:
        # si se hiciera, cualquiera en la misma red que un equipo registrado se
        # llevaria su sesion. El host compartido sirve para el estado estricto.
        token = self._token_from_request(request)
        peer = self._peer_ip(request)
        reply = await self.filter.handle(wire, token, peer)
        if reply is None:
            return web.Response(status=400, text="consulta no valida")
        return web.Response(
            body=reply,
            content_type=DOH_CONTENT_TYPE,
            headers={"Cache-Control": "max-age=0", "X-Device": token or "desconocido"},
        )

    async def handle_health(self, request: web.Request) -> web.StreamResponse:
        return web.json_response(
            {
                "ok": True,
                "uptime": int(time.time() - self.started_at),
                "devices": len(self.store.list()),
                "licenses": self.licenses.count(),
                "captive_ip": self.config.captive_ip,
                "pendientes": len(self.store.pending_requests()),
                "stats": self.filter.stats(),
            }
        )

    async def handle_landing(self, request: web.Request) -> web.StreamResponse:
        """Portal cautivo.

        Si la peticion llega por un host de equipo, es su pagina. Si llega
        con cualquier otro host es porque el DNS resolvio algo bloqueado
        hacia aqui, y se identifica el equipo por su IP.
        """
        token = self._token_from_request(request)
        if token:
            return await self._device_page(request, token)
        if not self.config.captive_ip:
            raise web.HTTPFound("/activar")
        ip = self._peer_ip(request)
        resolved = await asyncio.to_thread(self.store.token_by_ip, ip)
        if resolved:
            return await self._device_page(request, resolved)
        # Sin token en el Host y sin equipo conocido: con el perfil unico esta es
        # la pantalla normal, no hace falta pedir ninguna referencia.
        if self.config.trust_ip:
            return await self._ip_page(request)
        return web.Response(
            text=manual_page(ip),
            content_type="text/html",
            headers={"Cache-Control": "no-store"},
        )

    def _device_view(self, token: str) -> dict[str, Any]:
        device = self.store.device(token)
        unlocked_until = int((device or {}).get("unlocked_until", 0))
        remaining = unlocked_until - int(time.time())
        return {
            "token": token,
            "label": (device or {}).get("label", ""),
            "conocido": device is not None,
            "modo": MODE_UNLOCKED if remaining > 0 else MODE_STRICT,
            "desbloqueado_hasta": unlocked_until if remaining > 0 else None,
            "horas_restantes": round(remaining / 3600, 2) if remaining > 0 else 0,
        }

    def _ip_view(self, ip: str) -> dict[str, Any]:
        """Estado de un telefono con el perfil unico: solo se sabe su IP.

        Es el mismo estado que ve un equipo con token, para que la pantalla sea
        la de siempre: su codigo, cuando caduca y si ya tiene salida.
        """
        return self.store.request_info_ip(ip)

    async def _ip_page(
        self, request: web.Request, banner: str = "", kind: str = ""
    ) -> web.StreamResponse:
        """Pantalla del telefono cuando no hay token: el perfil es el mismo para
        todos y lo unico que se sabe de el es la IP desde la que entra."""
        info = await asyncio.to_thread(self._ip_view, self._peer_ip(request))
        body = device_page(info, token="", banner=banner, kind=kind)
        return web.Response(
            text=body, content_type="text/html", headers={"Cache-Control": "no-store"}
        )

    async def _device_page(
        self, request: web.Request, token: str, banner: str = "", kind: str = ""
    ) -> web.StreamResponse:
        try:
            info = await asyncio.to_thread(self.store.request_info, token)
        except KeyError:
            info = {
                "token": token,
                "label": "",
                "codigo": "",
                "ip": self._peer_ip(request),
                "modo": MODE_STRICT,
                "visto": 0,
                "desbloqueado_hasta": 0,
            }
            if not banner:
                banner = "Este equipo no esta registrado. Contacta con el administrador."
                kind = "error"
        body = device_page(info, token=token, banner=banner, kind=kind)
        return web.Response(
            text=body, content_type="text/html", headers={"Cache-Control": "no-store"}
        )

    def _csrf(self, request: web.Request) -> str:
        cookie = request.cookies.get("bscsrf", "")
        if len(cookie) >= 16:
            return cookie
        return secrets.token_urlsafe(24)

    async def handle_activate_get(self, request: web.Request) -> web.StreamResponse:
        token = (request.match_info.get("token") or "").strip().lower()
        if not token:
            if self.config.trust_ip and self._peer_ip(request):
                return await self._ip_page(request)
            return await self.handle_token_form(request)
        return await self._device_page(request, token)

    async def handle_token_form(self, request: web.Request) -> web.StreamResponse:
        token = (request.query.get("t") or "").strip().lower()
        if token:
            return web.HTTPFound(f"/activar/{token}")
        return web.Response(
            text=manual_page(self._peer_ip(request)),
            content_type="text/html",
            headers={"Cache-Control": "no-store"},
        )

    async def handle_request_api(self, request: web.Request) -> web.StreamResponse:
        """El movil pide su codigo y consulta si ya le han autorizado.

        Con perfil por equipo se busca por token. Con el perfil unico no hay
        token, asi que el telefono se identifica por la IP desde la que pide.
        """
        token = (request.match_info.get("token") or "").strip().lower()
        nuevo = bool(request.query.get("nuevo"))
        try:
            if token:
                if nuevo:
                    await asyncio.to_thread(self.store.request, token)
                info = await asyncio.to_thread(self.store.request_info, token)
            else:
                ip = self._peer_ip(request)
                if not ip:
                    return web.json_response({"error": "sin_identificar"}, status=400)
                await asyncio.to_thread(self.store.request_ip, ip, nuevo)
                info = await asyncio.to_thread(self.store.request_info_ip, ip)
        except KeyError:
            return web.json_response({"error": "equipo_desconocido"}, status=404)
        return web.json_response(info, headers={"Cache-Control": "no-store"})

    @admin_required
    async def handle_generate(self, request: web.Request) -> web.StreamResponse:
        """Genera codigos sueltos para dejar un iPhone con acceso completo."""
        data = await request.json()
        hours = int(data.get("horas", self.config.request_hours))
        days = int(data.get("dias", 30))
        count = max(1, min(int(data.get("cantidad", 1)), 50))
        nuevos = [
            await asyncio.to_thread(self.codes.generate, hours, days) for _ in range(count)
        ]
        return web.json_response(
            {"ok": True, "horas": hours, "valido_dias": days, "codigos": nuevos}
        )

    async def handle_redeem(self, request: web.Request) -> web.StreamResponse:
        """El movil canjea el codigo que le ha dado el administrador.

        Con perfil por equipo se abre la ventana de ese token; con el perfil
        unico no hay token, asi que se abre la de la IP desde la que llega.
        """
        data = await request.json()
        code = str(data.get("codigo", "")).strip()
        token = str(data.get("token", "")).strip().lower()
        ip = self._peer_ip(request)
        if not self.codes.is_valid(code):
            return web.json_response({"error": "codigo_invalido"}, status=400)
        if token and not self.store.device(token):
            return web.json_response({"error": "equipo_desconocido"}, status=404)
        if not token and not ip:
            return web.json_response({"error": "sin_identificar"}, status=400)
        hours, entry = await asyncio.to_thread(self.codes.redeem, code, token, ip)
        if entry is None:
            return web.json_response(
                {"error": "codigo_no_valido", "detalle": "ese codigo no existe o ya se uso"},
                status=403,
            )
        if token:
            device = await asyncio.to_thread(self.store.unlock, token, "", hours)
        else:
            device = await asyncio.to_thread(self.store.unlock_ip, ip, "", hours)
        await asyncio.to_thread(self.codes.activate, code, hours, "canje")
        return web.json_response(
            {
                "ok": True,
                "horas": hours,
                "token": token,
                "ip": ip if not token else "",
                "label": device.get("label", ""),
                "unlocked_until": int(device["unlocked_until"]),
            }
        )

    @admin_required
    async def handle_revoke(self, request: web.Request) -> web.StreamResponse:
        """Deja de valer un codigo ya activado, sin tocar el resto del equipo."""
        data = await request.json()
        code = str(data.get("codigo", "")).strip()
        if not code:
            return web.json_response({"error": "codigo_vacio"}, status=400)
        entry = await asyncio.to_thread(self.codes.revoke, code)
        if not entry:
            return web.json_response({"error": "codigo_no_encontrado"}, status=404)
        return web.json_response({"ok": True, "codigo": code})

    async def handle_register_api(self, request: web.Request) -> web.StreamResponse:
        """El movil da de alta el codigo que se ha generado el mismo.

        Acepta el cuerpo de la web antigua ({code}) y ademas admite ?token= para
        atarlo al equipo, porque el portal cautivo ya sabe quien esta delante.
        """
        data = await request.json()
        code = str(data.get("code") or data.get("codigo") or "").strip()
        if not self.codes.is_valid(code):
            return web.json_response({"error": "codigo_invalido"}, status=400)
        token = (data.get("token") or request.query.get("token") or "").strip().lower()
        if token and not self.store.device(token):
            return web.json_response({"error": "equipo_desconocido"}, status=404)
        entrada = await asyncio.to_thread(
            self.codes.register, code, token, self._peer_ip(request)
        )
        return web.json_response(entrada, headers={"Cache-Control": "no-store"})

    async def handle_code_state(self, request: web.Request) -> web.StreamResponse:
        """Consulta el estado de un codigo. Solo el suyo: pide el codigo entero."""
        code = (request.match_info.get("codigo") or "").strip()
        if not self.codes.is_valid(code):
            return web.json_response({"error": "codigo_invalido"}, status=400)
        entrada = await asyncio.to_thread(self.codes.get, code)
        if entrada is None:
            return web.json_response({"error": "codigo_no_encontrado"}, status=404)
        return web.json_response(entrada, headers={"Cache-Control": "no-store"})

    @admin_required
    async def handle_codes_list(self, request: web.Request) -> web.StreamResponse:
        """Lista global de codigos, para el administrador.

        A diferencia de la web antigua, aqui no es publica: la decia cualquiera
        que visitara la pagina y se veian los codigos de todos los clientes.
        """
        return web.json_response(await asyncio.to_thread(self.codes.list))

    @admin_required
    async def handle_panel(self, request: web.Request) -> web.StreamResponse:
        """Panel del administrador: solicitudes, equipos, codigos y licencias."""
        requests = await asyncio.to_thread(self.store.pending_requests)
        devices = await asyncio.to_thread(self.store.list)
        licenses = await asyncio.to_thread(self.licenses.inventory)
        codigos = await asyncio.to_thread(self.codes.list)
        # La clave llega en la query, asi que hay que pasarsela a la pagina: si no,
        # los botones que llama el navegador se quedan sin autorizacion.
        key = request.query.get("k") or request.headers.get("X-Admin-Key") or ""
        body = admin_page(
            requests,
            devices,
            licenses,
            codigos,
            accesos=await asyncio.to_thread(self.store.ip_list),
            hours=self.config.request_hours,
            key=key,
        )
        return web.Response(
            text=body, content_type="text/html", headers={"Cache-Control": "no-store"}
        )

    @admin_required
    async def handle_ip_revoke(self, request: web.Request) -> web.StreamResponse:
        """Corta el acceso de un telefono con el perfil unico.

        No borra nada: deja la ventana a cero, de modo que ese telefono vuelve al
        estado de espera (solo YouTube, Telegram y la pagina del codigo).
        """
        ip = str(request.match_info.get("ip") or "").strip()
        if not ip:
            return web.json_response({"error": "ip_invalida"}, status=400)
        await asyncio.to_thread(self.store.set_ip_unlocked_until, ip, 0)
        return web.json_response({"ok": True, "ip": ip})

    async def _activar(
        self,
        code: str,
        hours: int,
        license_code: str,
        origen: str,
        ip_forzada: str = "",
    ) -> tuple[int, dict]:
        """Activa un codigo. Lo usan el panel y la API, para que se comporten igual.

        Un codigo puede pertenecer a un equipo con token (instalacion antigua), a
        un telefono con el perfil unico (que solo tiene IP) o a las dos cosas, si
        el telefono abrio la pagina de un equipo antiguo. Se abren TODAS las
        identidades que resuelve el codigo: si solo se abriera una, activarlo
        devolveria ok y el movil seguiria sin salida, que es lo que mas confunde.
        """
        registro = await asyncio.to_thread(self.codes.get, code)
        token = (registro or {}).get("token") or await asyncio.to_thread(
            self.store.find_by_request_code, code
        )
        ip = ip_forzada or (registro or {}).get("ip") or await asyncio.to_thread(
            self.store.find_ip_by_request_code, code
        )
        if not token and not ip:
            return 404, {"error": "codigo_no_encontrado"}

        etiquetas: list[str] = []
        hasta = 0
        if token and await asyncio.to_thread(self.store.device, token):
            device = await asyncio.to_thread(self.store.unlock, token, license_code, hours)
            hasta = int(device["unlocked_until"])
            etiquetas.append(f"equipo {token} ({device.get('label') or 'sin etiqueta'})")
        if ip:
            # El perfil unico identifica al telefono por su IP, con o sin token.
            acceso = await asyncio.to_thread(self.store.unlock_ip, ip, license_code, hours)
            hasta = max(hasta, int(acceso["unlocked_until"]))
            etiquetas.append(f"ip {ip}")

        if registro:
            await asyncio.to_thread(self.codes.activate, code, hours, origen)
        else:
            await asyncio.to_thread(self.store.deny, code)
        await asyncio.to_thread(self._sync_tunnel_firewall)
        return 0, {
            "ok": True,
            "token": token if isinstance(token, str) else "",
            "ip": ip if isinstance(ip, str) else "",
            "label": etiquetas[0] if etiquetas else "",
            "abierto": etiquetas,
            "unlocked_until": hasta,
            "hours": hours,
        }

    @admin_required
    async def handle_approve(self, request: web.Request) -> web.StreamResponse:
        data = await request.json()
        code = str(data.get("codigo", "")).strip()
        hours = int(data.get("horas", self.config.request_hours))
        license_code = str(data.get("licencia", "")).strip().upper()
        if not code:
            return web.json_response({"error": "codigo_vacio"}, status=400)
        if license_code:
            result = await asyncio.to_thread(self.licenses.check, license_code)
            if not result.ok:
                return web.json_response({"error": result.reason}, status=403)

        status, cuerpo = await self._activar(code, hours, license_code, "panel")
        return web.json_response(cuerpo, status=status or 200)

    @api_key_required(SCOPE_ACTIVAR)
    async def handle_api_activar(self, request: web.Request) -> web.StreamResponse:
        """Activa un codigo desde el servidor del cliente.

        Acepta el codigo tal cual lo ve el usuario. La IP no hace falta enviarla:
        se toma de la que registro el codigo. Si se envia, gana la del servidor.
        """
        data = await request.json()
        code = str(data.get("codigo") or data.get("code") or "").strip()
        if not code:
            return web.json_response({"error": "codigo_vacio"}, status=400)
        try:
            hours = int(data.get("horas", self.config.request_hours))
        except (TypeError, ValueError):
            return web.json_response({"error": "horas_invalidas"}, status=400)
        license_code = str(data.get("licencia", "")).strip().upper()
        if license_code:
            result = await asyncio.to_thread(self.licenses.check, license_code)
            if not result.ok:
                return web.json_response({"error": result.reason}, status=403)

        ip = str(data.get("ip", "")).strip()
        status, cuerpo = await self._activar(code, hours, license_code, "api", ip)
        if not status:
            cuerpo["api_key"] = request.get("api_key", {}).get("id", "")
        return web.json_response(cuerpo, status=status or 200)

    @api_key_required(SCOPE_CONSULTAR)
    async def handle_api_estado(self, request: web.Request) -> web.StreamResponse:
        """Consulta el estado de un codigo sin activarlo."""
        code = request.match_info["codigo"].strip()
        registro = await asyncio.to_thread(self.codes.get, code)
        if registro is None:
            return web.json_response({"error": "codigo_no_encontrado"}, status=404)
        cuerpo = dict(registro)
        cuerpo.pop("hash", None)
        return web.json_response(cuerpo)

    @api_key_required(SCOPE_REVOCAR)
    async def handle_api_revocar(self, request: web.Request) -> web.StreamResponse:
        data = await request.json()
        code = str(data.get("codigo") or data.get("code") or "").strip()
        hours = int(data.get("horas", 0))
        if not code:
            return web.json_response({"error": "codigo_vacio"}, status=400)
        registro = await asyncio.to_thread(self.codes.get, code)
        if registro is None:
            return web.json_response({"error": "codigo_no_encontrado"}, status=404)
        ip = registro.get("ip", "")
        await asyncio.to_thread(self.codes.revoke, code)
        if ip and hours >= 0:
            await asyncio.to_thread(self.store.set_ip_unlocked_until, ip, 0)
        return web.json_response({"ok": True, "codigo": code, "ip": ip})

    @admin_required
    async def handle_deny(self, request: web.Request) -> web.StreamResponse:
        data = await request.json()
        code = str(data.get("codigo", "")).strip()
        token = await asyncio.to_thread(self.store.deny, code)
        if token is None:
            return web.json_response({"error": "codigo_no_encontrado"}, status=404)
        return web.json_response({"ok": True, "token": token})

    @admin_required
    async def handle_state(self, request: web.Request) -> web.StreamResponse:
        token = (request.match_info.get("token") or "").strip().lower()
        return web.json_response(self._device_view(token))

    @admin_required
    async def handle_unlock_api(self, request: web.Request) -> web.StreamResponse:
        data = await request.json()
        token = str(data.get("token", "")).strip().lower()
        code = str(data.get("code", "")).strip().upper()
        hours = int(data.get("hours", self.config.unlock_hours))
        if not self.store.device(token):
            return web.json_response({"error": "dispositivo_desconocido"}, status=404)
        result = await asyncio.to_thread(self.licenses.check, code)
        if not result.ok:
            return web.json_response({"error": result.reason}, status=403)
        device = await asyncio.to_thread(self.store.unlock, token, code, hours)
        return web.json_response(
            {
                "ok": True,
                "token": token,
                "unlocked_until": int(device["unlocked_until"]),
                "hours": hours,
            }
        )

    @admin_required
    async def handle_lock_api(self, request: web.Request) -> web.StreamResponse:
        token = (request.match_info.get("token") or "").strip().lower()
        device = await asyncio.to_thread(self.store.set_unlocked_until, token, 0)
        return web.json_response({"ok": True, "token": device["token"], "unlocked_until": 0})

    async def handle_profile(self, request: web.Request) -> web.StreamResponse:
        if not self._authorized(request):
            return web.Response(status=401, text="no autorizado")
        token = (request.match_info.get("token") or "").strip().lower()
        if not self.store.device(token):
            return web.Response(status=404, text="dispositivo desconocido")
        profile = build_profile(self.config, token, self.organization)
        return web.Response(
            body=profile,
            content_type="application/x-apple-aspen-config",
            headers={
                "Content-Disposition": f'attachment; filename="perfil-{token}.mobileconfig"',
                "Cache-Control": "no-store",
            },
        )

    async def handle_shared_profile(self, request: web.Request) -> web.StreamResponse:
        """Un unico perfil para todos los telefonos.

        Todos apuntan al mismo DoH y el equipo se reconoce por su IP, asi que da
        igual en que iPhone se instale. El identificador no lleva token a
        proposito: si lo llevara, al reinstalarlo en otro telefono seguiria atado
        al equipo viejo.
        """
        if not self._authorized(request):
            return web.Response(status=401, text="no autorizado")
        profile = build_profile(
            self.config, "todos", self.organization, doh_url=self.config.shared_doh_url()
        )
        return web.Response(
            body=profile,
            content_type="application/x-apple-aspen-config",
            headers={
                "Content-Disposition": 'attachment; filename="bloqueoservi.mobileconfig"',
                "Cache-Control": "no-store",
            },
        )

    async def handle_short_config(self, request: web.Request) -> web.StreamResponse:
        """URL corta publica para instalar el perfil comun desde el iPhone."""
        profile = build_profile(
            self.config, "todos", self.organization, doh_url=self.config.shared_doh_url()
        )
        return web.Response(
            body=profile,
            content_type="application/x-apple-aspen-config",
            headers={
                "Content-Disposition": 'attachment; filename="config.mobileconfig"',
                "Cache-Control": "no-store",
            },
        )

    async def handle_vpn_test_profile(self, request: web.Request) -> web.StreamResponse:
        """Perfil minimo solo-VPN, para diagnosticar IKEv2 en iOS."""
        if not self._authorized(request):
            return web.Response(status=401, text="no autorizado")
        profile = build_vpn_test_profile(self.config)
        return web.Response(
            body=profile,
            content_type="application/x-apple-aspen-config",
            headers={
                "Content-Disposition": 'attachment; filename="vpn-test.mobileconfig"',
                "Cache-Control": "no-store",
            },
        )

    def build_app(self) -> web.Application:
        app = web.Application(client_max_size=64 * 1024)
        app["config"] = self.config
        app["service"] = self
        app.router.add_get("/", self.handle_landing)
        app.router.add_get("/activar", self.handle_activate_get)
        # La web de codigos, con el mismo nombre que tenia antes. Aqui el
        # telefono genera su codigo y lo registra con su IP.
        app.router.add_get("/codes.html", self.handle_activate_get)
        app.router.add_get("/config", self.handle_short_config)
        app.router.add_get("/activar/{token}", self.handle_activate_get)
        app.router.add_route("*", self.config.doh_path, self.handle_doh)
        app.router.add_get("/salud", self.handle_health)
        app.router.add_get("/panel", self.handle_panel)
        app.router.add_get("/api/pedido", self.handle_request_api)
        app.router.add_get("/api/pedido/{token}", self.handle_request_api)
        app.router.add_post("/api/register", self.handle_register_api)
        app.router.add_get("/api/estado-codigo/{codigo}", self.handle_code_state)
        app.router.add_get("/api/list", self.handle_codes_list)
        app.router.add_post("/api/admin/ok", self.handle_approve)
        app.router.add_post("/api/v1/activar", self.handle_api_activar)
        app.router.add_get("/api/v1/estado/{codigo}", self.handle_api_estado)
        app.router.add_post("/api/v1/revocar", self.handle_api_revocar)
        app.router.add_post("/api/admin/no", self.handle_deny)
        app.router.add_post("/api/admin/revocar", self.handle_revoke)
        app.router.add_post("/api/admin/generar", self.handle_generate)
        app.router.add_post("/api/canjear", self.handle_redeem)
        app.router.add_get("/api/estado/{token}", self.handle_state)
        app.router.add_post("/api/desbloquear", self.handle_unlock_api)
        app.router.add_post("/api/bloquear/{token}", self.handle_lock_api)
        app.router.add_post("/api/admin/ip/{ip}", self.handle_ip_revoke)
        app.router.add_get("/perfil/vpn-test.mobileconfig", self.handle_vpn_test_profile)
        app.router.add_get("/perfil/bloqueoservi.mobileconfig", self.handle_shared_profile)
        app.router.add_get("/perfil/{token}.mobileconfig", self.handle_profile)
        return app
