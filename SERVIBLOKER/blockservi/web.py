from __future__ import annotations

import asyncio
import hmac
import hashlib
import ipaddress
import json
import os
import secrets
import time
from typing import Any

from aiohttp import web

from .apikeys import SCOPE_ACTIVAR, SCOPE_CONSULTAR, SCOPE_REVOCAR, ApiKeys
from .codes import Codes
from .config import Config
from .dnsfilter import Filter
from .licenses import Licenses
from .portal import admin_page, device_page, manual_page, login_page, virtual_panel
from .profile import build_profile
from .rules import MODE_STRICT, MODE_UNLOCKED
from .store import Store
from .virtual import VirtualState
from .persistence import file_lock
from .profile import load_identity

DOH_CONTENT_TYPE = "application/dns-message"


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def admin_required(handler):
    """Exige la clave de administracion por cabecera X-Admin-Key o por ?k=."""

    async def wrapper(request: web.Request) -> web.StreamResponse:
        service: "Service" = request.app["service"]
        if not service._authorized(request):
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
        organization: str = "IBLOKER",
    ) -> None:
        self.config = config
        self.filter = dns_filter
        self.store = store
        self.licenses = licenses
        self.codes = codes
        self.api_keys = api_keys
        self.organization = organization
        self.virtual = VirtualState(config.data_dir)
        self.started_at = time.time()

    def _peer_ip(self, request: web.Request) -> str:
        remote = request.remote or ""
        try:
            peer = ipaddress.ip_address(remote)
            trusted = [ipaddress.ip_network(net) for net in self.config.trusted_proxies]
            if not any(peer in net for net in trusted):
                return str(peer)
            # Descartar proxies desde la derecha. CF-Connecting-IP nunca es autoridad.
            chain = [ipaddress.ip_address(part.strip()) for part in request.headers.get("X-Forwarded-For", "").split(",") if part.strip()]
            for candidate in reversed(chain):
                if not any(candidate in net for net in trusted):
                    return str(candidate)
            return str(peer)
        except ValueError:
            return remote

    def _token_from_request(self, request: web.Request) -> str | None:
        token = request.match_info.get("device_token")
        if token:
            return token
        host = (request.headers.get("Host") or "").split(":")[0]
        return self.config.token_from_dns_host(host)

    def _session_signature(self, payload: str) -> str:
        return hmac.new(self.config.admin_key.encode(), payload.encode(), hashlib.sha256).hexdigest()

    def _authorized(self, request: web.Request) -> bool:
        provided = request.headers.get("X-Admin-Key", "")
        if self.config.legacy_admin_query:
            provided = provided or request.query.get("k", "")
        if provided and hmac.compare_digest(provided, self.config.admin_key):
            return True
        cookie = request.cookies.get("iblocker_session", "")
        try:
            issued, nonce, signature = cookie.split(".")
            valid = (0 <= time.time() - int(issued) < 8 * 3600 and
                     hmac.compare_digest(signature, self._session_signature(issued + "." + nonce)))
        except (ValueError, TypeError):
            return False
        if request.method not in ("GET", "HEAD"):
            valid = valid and request.headers.get("X-IBLOKER-Request") == "1"
        return bool(valid)

    def _sync_tunnel_firewall(self) -> None:
        # El controlador independiente reconcilia en <=5 s. La web no ejecuta root/sudo.
        return None

    async def handle_login(self, request):
        if request.method == "GET":
            return web.Response(text=login_page(), content_type="text/html")
        if not self.virtual.allow("login:" + self._peer_ip(request), 10):
            raise web.HTTPTooManyRequests()
        data = await request.json()
        if not hmac.compare_digest(str(data.get("key", "")), self.config.admin_key):
            raise web.HTTPUnauthorized()
        payload = f"{int(time.time())}.{secrets.token_hex(24)}"
        response = web.json_response({"ok": True})
        response.set_cookie("iblocker_session", payload + "." + self._session_signature(payload),
                            secure=True, httponly=True, samesite="Strict", max_age=8 * 3600, path="/")
        return response

    async def handle_logout(self, request):
        if not self._authorized(request):
            raise web.HTTPUnauthorized()
        response = web.json_response({"ok": True})
        response.del_cookie("iblocker_session", path="/")
        return response

    @admin_required
    async def handle_virtual_activity(self, request):
        return web.json_response({"dns": self.filter.log.recent(50, only_blocked=False),
                                  "stats": self.filter.stats(), "controller": self.virtual.observed()})

    @admin_required
    async def handle_virtual_devices(self, request):
        observed = self.virtual.observed()
        rows = []
        contacts = self.virtual.contacts()
        for device in self.store.list():
            token = device["token"]
            sessions = [sa for sa in observed.get("sessions", []) if sa["token"] == token]
            identity = None
            if self.config.vpn_enabled:
                try:
                    identity = load_identity(self.config, token, allow_expired=True)
                except (FileNotFoundError, ValueError):
                    pass
            contact = contacts.get(token, {})
            rows.append({**device, "last_contact": max(device.get("last_seen", 0), contact.get("at", 0)),
                         "public_ip": contact.get("public_ip", "") or device.get("last_ip", ""), "unlocked_until": self.store.effective_until(token), "state": self.store.state(token),
                         "dns": "seen" if device.get("last_seen") else "never_seen",
                         "vpn": "connected" if sessions and observed.get("fresh") and observed.get("healthy") else "unknown" if not observed.get("fresh") else "disconnected",
                         "sessions": sessions, "profile_ready": not self.config.vpn_enabled or bool(identity and identity["expires_at"] > time.time()),
                         "credential_expires_at": identity["expires_at"] if identity else 0,
                         "activation_url": self.config.activation_url(token)})
        return web.json_response({"devices": rows, "controller": observed, "vpn_enabled": self.config.vpn_enabled})

    @admin_required
    async def handle_virtual_create(self, request):
        data = await request.json()
        device = await asyncio.to_thread(self.store.add, str(data.get("label", "")))
        return web.json_response({"ok": True, "token": device["token"],
                                  "profile_url": f"/perfil/{device['token']}.mobileconfig",
                                  "provisioning": self.config.vpn_enabled}, status=201)

    @admin_required
    async def handle_virtual_action(self, request):
        token = request.match_info["token"]
        action = request.match_info["action"]
        if not self.store.device(token):
            raise web.HTTPNotFound()
        data = await request.json()
        if action == "unlock":
            hours = int(data.get("hours", 24))
            license_code = str(data.get("license", ""))
            if license_code and not self.licenses.check(license_code).ok:
                raise web.HTTPForbidden(text="licencia_invalida")
            await asyncio.to_thread(self.store.unlock, token, license_code, hours)
        elif action == "lock":
            await asyncio.to_thread(self.store.set_unlocked_until, token, 0)
        elif action == "revoke":
            await asyncio.to_thread(self.store.revoke_credential, token)
        else:
            raise web.HTTPNotFound()
        return web.json_response({"ok": True, "state": self.store.state(token), "firewall": "pending_reconciliation"})

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
            headers={"Cache-Control": "max-age=0"},
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
        resolved = None  # La IP pública nunca revela la identidad de otro dispositivo.
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
        unlocked_until = self.store.effective_until(token)
        remaining = unlocked_until - int(time.time())
        return {
            "token": token,
            "label": (device or {}).get("label", ""),
            "conocido": device is not None,
            "modo": self.store.mode(token),
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

    def _device_request_code(self, token, ip):
        with file_lock(os.path.join(self.config.data_dir, "activation.lock")):
            # Evitar colisiones con códigos históricos/pregenerados, además de solicitudes Store.
            for _ in range(64):
                code = self.store.request(token)
                existing = self.codes.get(code)
                if existing and (existing.get("token") != token or existing.get("usado_at") or existing.get("revoked_at")):
                    self.store._clear_request(token)
                    continue
                try:
                    self.codes.register(code, token, ip)
                    return code
                except ValueError:
                    self.store._clear_request(token)
            raise ValueError("no_quedan_codigos_disponibles")

    async def handle_request_api(self, request: web.Request) -> web.StreamResponse:
        """El movil pide su codigo y consulta si ya le han autorizado.

        Con perfil por equipo se busca por token. Con el perfil unico no hay
        token, asi que el telefono se identifica por la IP desde la que pide.
        """
        token = (request.match_info.get("token") or "").strip().lower()
        if not self.virtual.allow("request:" + self._peer_ip(request), 120, 60):
            raise web.HTTPTooManyRequests()
        nuevo = bool(request.query.get("nuevo"))
        try:
            if token:
                if self.store.state(token) == "REVOKED":
                    raise web.HTTPForbidden(text="credencial_revocada")
                if nuevo:
                    await asyncio.to_thread(self._device_request_code, token, self._peer_ip(request))
                info = await asyncio.to_thread(self.store.request_info, token)
            else:
                if not self.config.trust_ip:
                    raise web.HTTPUnauthorized(text="perfil_individual_requerido")
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
        if not token and (not self.config.trust_ip or not ip):
            return web.json_response({"error": "sin_identificar"}, status=400)
        if token and self.store.state(token) == "REVOKED":
            raise web.HTTPForbidden(text="credencial_revocada")
        if not self.virtual.allow("redeem:" + self._peer_ip(request), 10):
            raise web.HTTPTooManyRequests()
        result = await asyncio.to_thread(self._redeem_transaction, code, token, ip)
        if result is None:
            return web.json_response({"error": "codigo_no_valido"}, status=403)
        return web.json_response(result)

    @admin_required
    async def handle_revoke(self, request: web.Request) -> web.StreamResponse:
        """Revoca el código y la autorización de su identidad asociada."""
        data = await request.json()
        code = str(data.get("codigo", "")).strip()
        if not code:
            return web.json_response({"error": "codigo_vacio"}, status=400)
        if not await asyncio.to_thread(self._revoke_code, code):
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
        if not token and not self.config.trust_ip:
            raise web.HTTPUnauthorized(text="perfil_individual_requerido")
        if token and self.store.state(token) == "REVOKED":
            raise web.HTTPForbidden()
        if not self.virtual.allow("register:" + self._peer_ip(request), 30):
            raise web.HTTPTooManyRequests()
        entrada = await asyncio.to_thread(
            self.codes.register, code, token, self._peer_ip(request)
        )
        return web.json_response({"id": entrada["id"], "active": False}, headers={"Cache-Control": "no-store"})

    async def handle_code_state(self, request: web.Request) -> web.StreamResponse:
        """Consulta el estado de un codigo. Solo el suyo: pide el codigo entero."""
        code = (request.match_info.get("codigo") or "").strip()
        if not self.codes.is_valid(code):
            return web.json_response({"error": "codigo_invalido"}, status=400)
        entrada = await asyncio.to_thread(self.codes.get, code)
        if entrada is None:
            return web.json_response({"error": "codigo_no_encontrado"}, status=404)
        token = request.headers.get("X-Device-Token", "")
        if entrada.get("token"):
            if not hmac.compare_digest(token, entrada["token"]):
                raise web.HTTPNotFound()
        elif not self.config.trust_ip or entrada.get("ip") != self._peer_ip(request):
            raise web.HTTPNotFound()
        active = entrada["active"] and (self.store.mode(token) == MODE_UNLOCKED if token else self.store.mode_for("", self._peer_ip(request)) == MODE_UNLOCKED)
        return web.json_response({"id": code, "active": active,
                                  "expires_at": entrada["expires_at"]}, headers={"Cache-Control": "no-store"})

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
        # La sesión HttpOnly autentica el panel; nunca se inserta admin_key en HTML.
        key = ""
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
            text=body.replace("</main>", virtual_panel() + "</main>"), content_type="text/html", headers={"Cache-Control": "no-store"}
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

    def _activate_transaction(self, code, hours, license_code, origen, ip_forzada=""):
        if not 1 <= int(hours) <= 2160:
            raise ValueError("horas_invalidas")
        with file_lock(os.path.join(self.config.data_dir, "activation.lock")):
            registro = self.codes.get(code)
            if registro and (registro.get("usado_at") or registro.get("revoked_at")):
                return 409, {"error": "codigo_ya_utilizado_o_revocado"}
            token = (registro or {}).get("token") or self.store.find_by_request_code(code)
            ip = (registro or {}).get("ip") or self.store.find_ip_by_request_code(code)
            # Los clientes API no pueden redirigir una solicitud a una IP diferente.
            if ip_forzada and ip_forzada != ip:
                return 400, {"error": "ip_no_coincide"}
            if token:
                if self.store.state(token) == "REVOKED":
                    return 403, {"error": "credencial_revocada"}
            elif not self.config.trust_ip or not ip:
                return 404, {"error": "codigo_no_encontrado"}
            if registro:
                self.codes.activate(code, hours, origen)
            self.store.deny(code)
            # Si el proceso se interrumpe tras consumir, no se concede acceso nuevo.
            device = self.store.unlock(token, license_code, hours) if token else self.store.unlock_ip(ip, license_code, hours)
            return 0, {"ok": True, "token": token or "", "ip": "" if token else ip,
                       "label": device.get("label", ""), "abierto": [token or ip],
                       "unlocked_until": self.store.effective_until(token) if token else device["unlocked_until"], "hours": hours}

    async def _activar(self, code, hours, license_code, origen, ip_forzada=""):
        return await asyncio.to_thread(self._activate_transaction, code, hours, license_code, origen, ip_forzada)

    def _revoke_code(self, code):
        with file_lock(os.path.join(self.config.data_dir, "activation.lock")):
            record = self.codes.get(code)
            if not record or not self.codes.revoke(code):
                return False
            token = record.get("token")
            if token and self.store.device(token):
                self.store.set_unlocked_until(token, 0)
            elif self.config.trust_ip and record.get("ip"):
                self.store.set_ip_unlocked_until(record["ip"], 0)
            return True

    def _redeem_transaction(self, code, token, ip):
        with file_lock(os.path.join(self.config.data_dir, "activation.lock")):
            if token and self.store.state(token) == "REVOKED":
                return None
            hours, entry = self.codes.redeem(code, token, ip)
            if entry is None:
                return None
            self.codes.activate(code, hours, "canje")
            device = self.store.unlock(token, "", hours) if token else self.store.unlock_ip(ip, "", hours)
            return {"ok": True, "horas": hours, "token": token, "ip": "" if token else ip,
                    "label": device.get("label", ""), "unlocked_until": device["unlocked_until"]}

    @admin_required
    async def handle_approve(self, request: web.Request) -> web.StreamResponse:
        data = await request.json()
        code = str(data.get("codigo", "")).strip()
        hours = int(data.get("horas", self.config.request_hours))
        license_code = str(data.get("licencia", "")).strip().upper()
        if not code:
            return web.json_response({"error": "codigo_vacio"}, status=400)
        if data.get("individual_only"):
            record = await asyncio.to_thread(self.codes.get, code)
            owner = (record or {}).get("token") or await asyncio.to_thread(self.store.find_by_request_code, code)
            if not owner or not await asyncio.to_thread(self.store.device, owner):
                return web.json_response({"error": "perfil_individual_requerido"}, status=403)
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
        if not code:
            return web.json_response({"error": "codigo_vacio"}, status=400)
        registro = await asyncio.to_thread(self.codes.get, code)
        if registro is None:
            return web.json_response({"error": "codigo_no_encontrado"}, status=404)
        await asyncio.to_thread(self._revoke_code, code)
        return web.json_response({"ok": True, "codigo": code})

    @admin_required
    async def handle_deny(self, request: web.Request) -> web.StreamResponse:
        data = await request.json()
        code = str(data.get("codigo", "")).strip()
        token = await asyncio.to_thread(self.store.deny, code)
        found = await asyncio.to_thread(self.codes.revoke, code)
        if token is None and not found:
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
        if self.store.state(token) == "REVOKED":
            raise web.HTTPForbidden(text="credencial_revocada")
        try:
            profile = build_profile(self.config, token, self.organization, profile_uuid=self.store.device(token).get("profile_uuid"), wifi=(await request.json()).get("wifi") if request.method == "POST" else None)
        except FileNotFoundError:
            return web.json_response({"error": "certificado_pendiente"}, status=409)
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
        if not self.config.trust_ip:
            raise web.HTTPGone(text="use_perfil_individual")
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
        if not self.config.trust_ip:
            raise web.HTTPGone(text="use_perfil_individual")
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
        raise web.HTTPGone(text="use_perfil_individual_con_certificado")

    def build_app(self) -> web.Application:
        @web.middleware
        async def guard(request, handler):
            try:
                # CSRF: cabecera no simple + mismo origen en login y escrituras de cookie.
                if request.method not in ("GET", "HEAD", "OPTIONS"):
                    if request.content_type == "application/json":
                        data = await request.json()
                        if not isinstance(data, dict):
                            raise ValueError("JSON debe ser objeto")
                    origin = request.headers.get("Origin")
                    if origin and origin != self.config.portal_origin():
                        raise web.HTTPForbidden(text="origen_invalido")
                if request.path == "/panel" and not self._authorized(request):
                    raise web.HTTPFound("/login")
                result = await handler(request)
            except (ValueError, TypeError, json.JSONDecodeError):
                result = web.json_response({"error": "datos_invalidos"}, status=400)
            except KeyError:
                result = web.json_response({"error": "no_encontrado"}, status=404)
            result.headers["Referrer-Policy"] = "no-referrer"
            result.headers["X-Content-Type-Options"] = "nosniff"
            result.headers["Cache-Control"] = "no-store"
            result.headers["X-Frame-Options"] = "DENY"
            return result
        app = web.Application(client_max_size=64 * 1024, middlewares=[guard])
        app["config"] = self.config
        app["service"] = self
        app.router.add_get("/login", self.handle_login)
        app.router.add_post("/login", self.handle_login)
        app.router.add_post("/logout", self.handle_logout)
        app.router.add_get("/api/virtual/activity", self.handle_virtual_activity)
        app.router.add_get("/api/virtual/devices", self.handle_virtual_devices)
        app.router.add_post("/api/virtual/devices", self.handle_virtual_create)
        app.router.add_post("/api/virtual/devices/{token}/{action}", self.handle_virtual_action)
        app.router.add_get("/", self.handle_landing)
        app.router.add_get("/activar", self.handle_activate_get)
        # La web de codigos, con el mismo nombre que tenia antes. Aqui el
        # telefono genera su codigo y lo registra con su IP.
        app.router.add_get("/codes.html", self.handle_activate_get)
        app.router.add_get("/config", self.handle_short_config)
        app.router.add_get("/activar/{token}", self.handle_activate_get)
        app.router.add_route("*", self.config.doh_path, self.handle_doh)
        app.router.add_route("*", self.config.doh_path + "/{device_token}", self.handle_doh)
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
        app.router.add_post("/perfil/{token}.mobileconfig", self.handle_profile)
        return app
