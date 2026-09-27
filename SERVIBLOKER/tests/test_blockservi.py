from __future__ import annotations

import asyncio
import json
import os
import plistlib
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiohttp.test_utils import TestClient, TestServer
from dnslib import A, DNSQuestion, DNSRecord, QTYPE, RCODE, RR

from blockservi.cli import Components
from blockservi.codes import Codes
from blockservi.config import load as load_config
from blockservi.licenses import Licenses
from blockservi.profile import build_profile
from blockservi.querylog import QueryLog
from blockservi.rules import MODE_STRICT, MODE_UNLOCKED, Policy, normalize
from blockservi.store import Store

POLICY_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "blockservi", "policy.json")

SPEC = {
    "strict_push": True,
    "deny_always": ["itunes.apple.com", "ls.apple.com", "=fmzmobile.icloud.com", "re:^doh\\."],
    "allow_strict": ["=portal.ejemplo.com"],
    "allow_strict_optional": ["fcm.googleapis.com"],
    "blocked_qtypes": ["PTR", "DS"],
}


class FakeUpstream:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.hits = 0
        self.misses = 0

    def stats(self) -> dict[str, int]:
        return {"hits": self.hits, "misses": self.misses, "cache": 0}

    async def resolve(self, wire: bytes) -> bytes:
        self.calls.append(str(DNSRecord.parse(wire).q.qname).lower())
        query = DNSRecord.parse(wire)
        reply = DNSRecord.question(str(query.q.qname), QTYPE[int(query.q.qtype)])
        reply.header.id = query.header.id
        reply.header.qr = 1
        reply.header.rd = 0
        reply.header.ra = 1
        reply.add_answer(RR("ns.example.", QTYPE.A, rdata=A("203.0.113.7"), ttl=120))
        return reply.pack()


def make_config(directory: str, token: str = "aabbccddeeff", captive_ip: str = ""):
    path = os.path.join(directory, "blockservi.ini")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            f"""[general]
domain = ejemplo.com
portal_host = app.ejemplo.com
device_dns_suffix = dns.ejemplo.com
admin_key = clave-de-prueba
data_dir = {directory}
state_file = {directory}/devices.json
licenses_file = {directory}/licenses.json
policy_file = {POLICY_PATH}
log_file = {directory}/blocked.log
unlock_hours = 24
captive_ip = {captive_ip}
request_hours = 24

[network]
http_host = 127.0.0.1
http_port = 0
plain_host = 127.0.0.1
plain_port = 0

[upstream]
doh =
udp =
"""
        )
    return load_config(path)


def test_rules():
    assert normalize(" YouTube.com. ") == "youtube.com"
    policy = Policy(SPEC)
    assert not policy.decide("youtube.com", MODE_STRICT).allow
    assert not policy.decide("m.youtube.com", MODE_STRICT).allow
    assert not policy.decide("t.me", MODE_STRICT).allow
    assert policy.decide("t.me", MODE_UNLOCKED).allow
    assert not policy.decide("fmzmobile.icloud.com", MODE_STRICT).allow
    assert not policy.decide("sub.itunes.apple.com", MODE_UNLOCKED).allow
    assert not policy.decide("doh.ejemplo.net", MODE_UNLOCKED).allow
    assert policy.decide("fcm.googleapis.com", MODE_STRICT).allow
    assert policy.decide("cualquier-cosa.net", MODE_UNLOCKED).allow
    assert not policy.decide("cualquier-cosa.net", MODE_STRICT).allow
    assert policy.check_qtype("DS") is not None
    assert policy.check_qtype("A") is None
    policy.spec["strict_push"] = False
    assert not Policy(SPEC | {"strict_push": False}).decide("fcm.googleapis.com", MODE_STRICT).allow


def test_policy_lists():
    policy = Policy.load(POLICY_PATH)
    policy.ensure_allowed(["app.ejemplo.com", "dns.ejemplo.com"])
    must_pass_strict = [
        "app.ejemplo.com",
        "dev-aabb.dns.ejemplo.com",
    ]
    for name in must_pass_strict:
        assert policy.decide(name, MODE_STRICT).allow, name
    must_fail_always = [
        "ibooks.apple.com",
        "p72-fmip.icloud.com",
        "fmip.fe2.apple-dns.net",
        "itunes.apple.com",
        "xp.apple.com",
        "books.apple.com",
        "ls.apple.com",
        "gspe35-ssl.ls.apple.com",
        "p01-contactsync.icloud.com",
        "dns.google",
        "cloudflare-dns.com",
    ]
    for name in must_fail_always:
        assert not policy.decide(name, MODE_UNLOCKED).allow, name
        assert not policy.decide(name, MODE_STRICT).allow, name
    for name in ("appleid.apple.com", "idmsa.apple.com", "gsa.apple.com", "account.apple.com"):
        assert policy.decide(name, MODE_UNLOCKED).allow, name
    for name in ("example.org", "www.instagram.com", "tiktok.com", "x.com"):
        assert not policy.decide(name, MODE_STRICT).allow, name


def test_config_tokens():
    with tempfile.TemporaryDirectory() as directory:
        config = make_config(directory)
        token = "aabbccddeeff"
        assert config.device_dns_host(token) == "dev-aabbccddeeff.dns.ejemplo.com"
        assert config.token_from_dns_host("dev-aabbccddeeff.dns.ejemplo.com") == token
        assert config.token_from_dns_host("DEV-AABBCCDDEEFF.DNS.EJEMPLO.COM") == token
        assert config.token_from_dns_host("dev-aabbccddeeff.dns.ejemplo.com:8443") is None
        assert config.token_from_dns_host("otro.dns.ejemplo.com") is None
        assert config.token_from_dns_host("dns.ejemplo.com") is None
        assert config.token_from_dns_host("app.ejemplo.com") is None
        assert config.activation_url(token) == "https://app.ejemplo.com/activar/aabbccddeeff"


def test_store_and_licenses():
    with tempfile.TemporaryDirectory() as directory:
        config = make_config(directory)
        store = Store(config.state_file)
        device = store.add("Recepcion", "ABCD-1234")
        token = device["token"]
        assert store.mode(token) == MODE_STRICT
        assert store.mode("999999999999") == MODE_STRICT
        assert store.mode(None) == MODE_STRICT

        code = "ABCD-1234"
        with open(config.licenses_file, "w", encoding="utf-8") as handle:
            json.dump({code: {"status": "active", "expires_at": int(time.time()) + 86400}}, handle)
        licenses = Licenses(config.licenses_file)
        assert licenses.check(code).ok
        assert not licenses.check("NO-EXISTE").ok
        assert not licenses.check("").ok

        updated = store.unlock(token, code, 24)
        assert updated["unlocked_until"] > time.time()
        assert store.mode(token) == MODE_UNLOCKED

        fresh = Store(config.state_file)
        assert fresh.mode(token) == MODE_UNLOCKED
        fresh.set_unlocked_until(token, 0)
        assert Store(config.state_file).mode(token) == MODE_STRICT

        assert store.delete(token)
        assert not store.delete(token)
        assert store.device(token) is None

    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "licenses.json")
        licenses = Licenses(path)
        assert not licenses.check("ABCD-1234").ok
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "REVOCADA": {"status": "revoked", "expires_at": int(time.time()) + 999},
                    "VENCIDA": {"status": "active", "expires_at": int(time.time()) - 10},
                },
                handle,
            )
        assert licenses.check("REVOCADA").reason == "licencia_revocada"
        assert licenses.check("VENCIDA").reason == "licencia_vencida"
        assert licenses.check("revocada").reason == "licencia_revocada"


async def filter_scenario():
    with tempfile.TemporaryDirectory() as directory:
        config = make_config(directory)
        store = Store(config.state_file)
        upstream = FakeUpstream()
        parts = Components(config)
        parts.upstream = upstream
        parts.filter.upstream = upstream
        device = store.add("Recepcion")
        token = device["token"]

        async def rcode(name: str, who: str | None = None, qtype: str = "A") -> int:
            reply = await parts.filter.handle(DNSRecord.question(name, qtype).pack(), who)
            assert reply is not None
            return int(DNSRecord.parse(reply).header.rcode)

        assert await rcode("youtube.com", token) == int(RCODE.NXDOMAIN)
        assert not any(call.rstrip(".") == "youtube.com" for call in upstream.calls)

        blocked = DNSRecord.parse(
            await parts.filter.handle(DNSRecord.question("instagram.com", "A").pack(), token)
        )
        assert int(blocked.header.rcode) == int(RCODE.NXDOMAIN)
        assert blocked.auth, "un bloqueo debe incluir SOA para que la app no reintente"

        store.unlock(token, "ABCD-1234", 24)
        assert await rcode("instagram.com", token) == int(RCODE.NOERROR)
        assert await rcode("itunes.apple.com", token) == int(RCODE.NXDOMAIN)
        assert await rcode("gspe35-ssl.ls.apple.com", token) == int(RCODE.NXDOMAIN)
        assert await rcode("youtube.com", token, "DS") == int(RCODE.NXDOMAIN)
        assert await rcode("youtube.com", None) == int(RCODE.NXDOMAIN)
        assert await rcode("instagram.com", None) == int(RCODE.NXDOMAIN)
        assert await rcode("instagram.com", "999999999999") == int(RCODE.NXDOMAIN)

        multi = DNSRecord()
        multi.add_question(DNSQuestion("youtube.com", QTYPE.A))
        multi.add_question(DNSQuestion("t.me", QTYPE.A))
        reply = await parts.filter.handle(multi.pack(), token)
        assert int(DNSRecord.parse(reply).header.rcode) == int(RCODE.FORMERR)

        assert await parts.filter.handle(b"no es dns", token) is None
        assert parts.filter.stats()["blocked"] >= 4
        entries = QueryLog(config.log_file).tail_file(20)
        assert any(entry["name"] == "instagram.com" for entry in entries)


def test_filter():
    asyncio.run(filter_scenario())


def test_profile():
    with tempfile.TemporaryDirectory() as directory:
        config = make_config(directory)
        data = build_profile(config, "aabbccddeeff")
        parsed = plistlib.loads(data)
        assert parsed["PayloadType"] == "Configuration"
        assert "PayloadRemovalDisallowed" not in parsed
        payload = parsed["PayloadContent"][0]
        assert payload["PayloadType"] == "com.apple.dnsSettings.managed"
        settings = payload["DNSSettings"]
        assert settings["DNSServerURLs"] == ["https://dev-aabbccddeeff.dns.ejemplo.com/dns-query"]
        assert settings["MatchDomains"] == []

        # El tunel VPN es lo que hace que el filtrado no se pueda saltar.
        # Sin el, el movil solo filtra nombres y las apps con DNS propio escapan.
        assert not any(
            p["PayloadType"] == "com.apple.vpn.managed" for p in parsed["PayloadContent"]
        ), "sin vpn_enabled no debe ir tunel en el perfil"

        # El payload que hace que iOS abra solo la pantalla del codigo. Sin el,
        # el movil abre una app bloqueada y se queda sin pagina: el DNS lo manda
        # al VPS, pero no hay certificado para el dominio que pidio.
        cautivo = [p for p in parsed["PayloadContent"] if p["PayloadType"] == "com.apple.captive-network-support"]
        assert len(cautivo) == 1
        assert cautivo[0]["PortalURL"] == "https://app.ejemplo.com/activar"
        assert cautivo[0]["SupportedURLs"] == ["http://captive.apple.com/hotspot-detect.html"]


async def web_scenario():
    with tempfile.TemporaryDirectory() as directory:
        config = make_config(directory, captive_ip="203.0.113.7")
        upstream = FakeUpstream()
        parts = Components(config)
        parts.upstream = upstream
        parts.filter.upstream = upstream
        # en produccion filtro y portal comparten el mismo Store
        store = parts.store
        service = parts.service
        device = store.add("Recepcion")
        token = device["token"]
        with open(config.licenses_file, "w", encoding="utf-8") as handle:
            json.dump({"ABCD-1234": {"status": "active", "expires_at": int(time.time()) + 86400}}, handle)

        client = TestClient(TestServer(service.build_app()))
        await client.start_server()

        async def doh(name: str, host: str, qtype: str = "A", ip: str = "88.13.24.7") -> int:
            wire = DNSRecord.question(name, qtype).pack()
            response = await client.post(
                "/dns-query",
                data=wire,
                headers={
                    "Host": host,
                    "Content-Type": "application/dns-message",
                    "X-Forwarded-For": ip,
                },
            )
            assert response.status == 200, await response.text()
            return int(DNSRecord.parse(await response.read()).header.rcode)

        async def doh_a(name: str, host: str, ip: str = "88.13.24.7") -> str:
            """Resolucion A completa, para ver a donde apunta lo bloqueado."""
            wire = DNSRecord.question(name, "A").pack()
            response = await client.post(
                "/dns-query",
                data=wire,
                headers={
                    "Host": host,
                    "Content-Type": "application/dns-message",
                    "X-Forwarded-For": ip,
                },
            )
            reply = DNSRecord.parse(await response.read())
            for rr in reply.rr:
                if int(rr.rtype) == 1:
                    return str(rr.rdata)
            return ""

        try:
            assert await doh("youtube.com", f"dev-{token}.dns.ejemplo.com") == int(RCODE.NOERROR)
            assert await doh("t.me", f"dev-{token}.dns.ejemplo.com") == int(RCODE.NOERROR)
            assert await doh("app.ejemplo.com", f"dev-{token}.dns.ejemplo.com") == int(RCODE.NOERROR)
            assert await doh("instagram.com", "dns.ejemplo.com") == int(RCODE.NOERROR)
            assert await doh("instagram.com", "atacante.example.com") == int(RCODE.NOERROR)

            # lo bloqueado responde con la IP del portal, no con NXDOMAIN
            assert await doh_a("instagram.com", f"dev-{token}.dns.ejemplo.com") == "203.0.113.7"
            # el bloqueo permanente no lleva al portal: no se arregla autorizando
            assert await doh_a("itunes.apple.com", f"dev-{token}.dns.ejemplo.com") == ""
            assert await doh("itunes.apple.com", f"dev-{token}.dns.ejemplo.com") == int(
                RCODE.NXDOMAIN
            )
            # AAAA se responde sin registros, un "no hay IPv6" normal
            assert await doh("instagram.com", f"dev-{token}.dns.ejemplo.com", "AAAA") == int(
                RCODE.NOERROR
            )
            assert await doh_a("instagram.com", f"dev-{token}.dns.ejemplo.com") == "203.0.113.7"

            # el movil pide su codigo
            page = await client.get("/activar/" + token)
            assert page.status == 200
            body = await page.text()
            assert "Recepcion" in body
            assert "Generar nuevo codigo" in body

            pedido = await client.get(f"/api/pedido/{token}?nuevo=1")
            assert pedido.status == 200
            code = (await pedido.json())["codigo"]
            assert len(code) == 6 and code.isdigit()

            # el codigo no cambia mientras sigue vigente
            again = await client.get(f"/api/pedido/{token}")
            assert (await again.json())["codigo"] == code

            # el portal cautivo identifica el equipo por la IP que hizo la consulta
            mobile_ip = "88.13.24.7"
            captive = await client.get(
                "/", headers={"Host": "instagram.com", "X-Forwarded-For": mobile_ip}
            )
            assert captive.status == 200
            captive_body = await captive.text()
            assert "Recepcion" in captive_body
            # La pagina es la de siempre: ids de siempre, generacion sola y sin IP.
            assert code in captive_body
            for marca in ('id="code"', 'id="code-slots"', 'id="btn-generate"', 'id="estado"'):
                assert marca in captive_body, marca
            assert "Generar nuevo codigo" in captive_body
            assert "Protegida" in captive_body
            assert 'id="ip-value"' not in captive_body
            # La IP real no sale en la pagina: por eso pone "Protegida".
            assert mobile_ip not in captive_body
            assert "/api/register" in captive_body
            assert f"equipo='{token}'" in captive_body

            # dos equipos distintos, cada uno con su codigo
            other_token = store.add("Almacen")["token"]
            await client.post(
                "/dns-query",
                data=DNSRecord.question("instagram.com", "A").pack(),
                headers={
                    "Host": f"dev-{other_token}.dns.ejemplo.com",
                    "Content-Type": "application/dns-message",
                    "X-Forwarded-For": "88.13.24.8",
                },
            )
            other_code = (
                await (await client.get(f"/api/pedido/{other_token}?nuevo=1")).json()
            )["codigo"]
            assert other_code != code
            second = await client.get(
                "/", headers={"Host": "tiktok.com", "X-Forwarded-For": "88.13.24.8"}
            )
            second_body = await second.text()
            assert other_code in second_body
            assert "Almacen" in second_body
            assert f"equipo='{other_token}'" in second_body

            # una IP desconocida, con el perfil unico, cae en la pantalla del
            # codigo: no hay que escribir ninguna referencia
            stranger = await client.get(
                "/", headers={"Host": "tiktok.com", "X-Forwarded-For": "1.2.3.4"}
            )
            stranger_body = await stranger.text()
            assert "Generar nuevo codigo" in stranger_body
            assert "Identifica tu" not in stranger_body

            unknown = await client.get("/", headers={"Host": "instagram.com", "X-Real-Ip": "1.2.3.4"})
            assert unknown.status == 200

            # el panel solo con la clave de administracion
            assert (await client.get("/panel")).status == 401
            panel = await client.get("/panel?k=clave-de-prueba")
            assert panel.status == 200
            panel_body = await panel.text()
            assert f"<code>{code}</code>" in panel_body
            assert "Recepcion" in panel_body
            # La clave se incrusta en la pagina: sin esto los botones del navegador
            # se quedan en 401 no_autorizado, porque la venia en la query.
            assert "clave='clave-de-prueba'" in panel_body
            assert 'api("/api/admin/' in panel_body
            assert 'api("/api/bloquear/' in panel_body
            assert "clave=''" not in panel_body
            # Y con la cabecera tambien se abre, con su clave puesta.
            panel_hdr = await client.get("/panel", headers={"X-Admin-Key": "clave-de-prueba"})
            assert "clave='clave-de-prueba'" in await panel_hdr.text()

            # rechazar y volver a pedir
            deny = await client.post(
                "/api/admin/no",
                json={"codigo": code},
                headers={"X-Admin-Key": "clave-de-prueba"},
            )
            assert (await deny.json())["ok"] is True
            assert (await (await client.get(f"/api/pedido/{token}")).json())["codigo"] == ""

            fresh = (await (await client.get(f"/api/pedido/{token}?nuevo=1")).json())["codigo"]
            assert fresh != code

            # autorizar consume la licencia indicada
            approve = await client.post(
                "/api/admin/ok",
                json={"codigo": fresh, "horas": 2, "licencia": "abcd-1234"},
                headers={"X-Admin-Key": "clave-de-prueba"},
            )
            assert approve.status == 200
            approved = await approve.json()
            assert approved["token"] == token
            assert approved["hours"] == 2
            assert store.mode(token) == MODE_UNLOCKED

            # una vez autorizado desaparece la solicitud
            assert (await (await client.get(f"/api/pedido/{token}")).json())["codigo"] == ""
            assert await doh("instagram.com", f"dev-{token}.dns.ejemplo.com") == int(RCODE.NOERROR)
            assert await doh_a("itunes.apple.com", f"dev-{token}.dns.ejemplo.com") == ""

            # el movil ve la pantalla de activado, como en la pagina de siempre
            unlocked_page = await client.get("/activar/" + token)
            assert "ACTIVADO" in await unlocked_page.text()

            # codigo desconocido
            missing = await client.post(
                "/api/admin/ok",
                json={"codigo": "000000"},
                headers={"X-Admin-Key": "clave-de-prueba"},
            )
            assert missing.status == 404

            # licencia invalida no autoriza
            other = (await (await client.get(f"/api/pedido/{token}?nuevo=1")).json())["codigo"]
            bad_lic = await client.post(
                "/api/admin/ok",
                json={"codigo": other, "licencia": "NO-EXISTE"},
                headers={"X-Admin-Key": "clave-de-prueba"},
            )
            assert bad_lic.status == 403
            assert store.mode(token) == MODE_UNLOCKED

            import base64

            wire = DNSRecord.question("youtube.com", "A").pack()
            get_doh = await client.get(
                "/dns-query?dns=" + base64.urlsafe_b64encode(wire).decode().rstrip("="),
                headers={"Host": f"dev-{token}.dns.ejemplo.com"},
            )
            assert get_doh.status == 200

            health = await client.get("/salud")
            assert (await health.json())["ok"] is True

            unauthorized = await client.get(f"/api/estado/{token}")
            assert unauthorized.status == 401
            authorized = await client.get(f"/api/estado/{token}?k=clave-de-prueba")
            assert (await authorized.json())["modo"] == MODE_UNLOCKED

            api_unlock = await client.post(
                "/api/desbloquear",
                json={"token": token, "code": "abcd-1234", "hours": 2},
                headers={"X-Admin-Key": "clave-de-prueba"},
            )
            assert (await api_unlock.json())["ok"] is True

            api_bad = await client.post(
                "/api/desbloquear",
                json={"token": token, "code": "NO-EXISTE"},
                headers={"X-Admin-Key": "clave-de-prueba"},
            )
            assert api_bad.status == 403

            api_lock = await client.post(
                f"/api/bloquear/{token}", headers={"X-Admin-Key": "clave-de-prueba"}
            )
            assert (await api_lock.json())["unlocked_until"] == 0
            assert store.mode(token) == MODE_STRICT

            # --- el codigo que genera el movil, como en la web de siempre ---
            # lo registra la propia pagina y nace pendiente
            generated = "761204"
            reg = await client.post(
                "/api/register",
                json={"code": generated, "token": token},
                headers={"X-Forwarded-For": "88.13.24.7"},
            )
            assert reg.status == 200
            assert (await reg.json())["id"] == generated
            assert (await reg.json())["active"] is False

            # con la IP y el token equivocados no lo acepta
            assert (
                await client.post(
                    "/api/register",
                    json={"code": "111222", "token": "no-existe"},
                )
            ).status == 404
            assert (await client.post("/api/register", json={"code": "123"})).status == 400

            # el movil consulta su propio estado y solo el suyo
            state = await client.get(f"/api/estado-codigo/{generated}")
            assert state.status == 200
            assert (await state.json())["pending"] is True
            assert (await (await client.get("/api/estado-codigo/000000")).json())["error"]

            # la lista global no es publica: antes la veia cualquiera
            assert (await client.get("/api/list")).status == 401
            listed = await client.get("/api/list?k=clave-de-prueba")
            assert listed.status == 200
            assert generated in [c["id"] for c in await listed.json()]

            # el administrador lo autoriza por ese codigo
            gen_approve = await client.post(
                "/api/admin/ok",
                json={"codigo": generated, "horas": 3},
                headers={"X-Admin-Key": "clave-de-prueba"},
            )
            assert gen_approve.status == 200
            assert (await gen_approve.json())["token"] == token
            assert store.mode(token) == MODE_UNLOCKED
            assert (await (await client.get(f"/api/estado-codigo/{generated}")).json())[
                "active"
            ] is True
            # y un codigo que no existe no se puede autorizar
            assert (
                await client.post(
                    "/api/admin/ok",
                    json={"codigo": "555444"},
                    headers={"X-Admin-Key": "clave-de-prueba"},
                )
            ).status == 404

            # revocar deja de valer sin tocar el resto del equipo
            revoked = await client.post(
                "/api/admin/revocar",
                json={"codigo": generated},
                headers={"X-Admin-Key": "clave-de-prueba"},
            )
            assert (await revoked.json())["ok"] is True
            after = await (await client.get(f"/api/estado-codigo/{generated}")).json()
            assert after["active"] is False and after["vencido"] is False
            assert (
                await client.post(
                    "/api/admin/revocar",
                    json={"codigo": "000000"},
                    headers={"X-Admin-Key": "clave-de-prueba"},
                )
            ).status == 404

            # el panel muestra la seccion de codigos
            panel_codes = await (await client.get("/panel?k=clave-de-prueba")).text()
            assert "CODIGOS" in panel_codes
            assert f"<code>{generated}</code>" in panel_codes

            # --- el generador: un codigo para dejar un iPhone con internet entero ---
            assert (await client.post("/api/admin/generar", json={"horas": 4})).status == 401
            made = await client.post(
                "/api/admin/generar",
                json={"horas": 8, "cantidad": 2, "dias": 15},
                headers={"X-Admin-Key": "clave-de-prueba"},
            )
            assert made.status == 200
            generado = await made.json()
            assert generado["horas"] == 8 and generado["valido_dias"] == 15
            assert len(generado["codigos"]) == 2
            code1, code2 = (c["id"] for c in generado["codigos"])
            assert code1 != code2
            assert store.mode(token) == MODE_UNLOCKED  # el panel no toca el equipo

            # el movil lo canjea y se queda sin filtro
            await client.post(f"/api/bloquear/{token}", headers={"X-Admin-Key": "clave-de-prueba"})
            assert store.mode(token) == MODE_STRICT
            redeem = await client.post(
                "/api/canjear",
                json={"codigo": code1, "token": token},
                headers={"X-Forwarded-For": "88.13.24.7"},
            )
            assert redeem.status == 200
            redimido = await redeem.json()
            assert redimido["horas"] == 8 and redimido["token"] == token
            assert store.mode(token) == MODE_UNLOCKED
            assert await doh("instagram.com", f"dev-{token}.dns.ejemplo.com") == int(RCODE.NOERROR)

            # un codigo es de un solo uso
            again = await client.post(
                "/api/canjear", json={"codigo": code1, "token": token}
            )
            assert again.status == 403
            # y lo que se ve es el estado, no un codigo ajeno
            assert (await (await client.get(f"/api/estado-codigo/{code1}")).json())["active"] is True
            assert (await (await client.get(f"/api/estado-codigo/{code2}")).json())["active"] is False
            # el panel los enseña como generados
            panel_gen = await (await client.get("/panel?k=clave-de-prueba")).text()
            assert f"<code>{code1}</code>" in panel_gen
            assert "GENERADO" in panel_gen and "MOVIL" in panel_gen
            # el movil ve el boton de canjear
            assert 'id="entrada"' in await (await client.get("/activar/" + token)).text()

            # codigos mal formados o de otro equipo
            assert (await client.post("/api/canjear", json={"codigo": "12", "token": token})).status == 400
            assert (
                await client.post("/api/canjear", json={"codigo": code2, "token": "nada"})
            ).status == 404

            profile_denied = await client.get(f"/perfil/{token}.mobileconfig")
            assert profile_denied.status == 401
            profile = await client.get(f"/perfil/{token}.mobileconfig?k=clave-de-prueba")
            assert profile.status == 200
            assert b"dev-" in await profile.read()

            # --- un unico perfil, valido en cualquier iPhone ---
            assert (await client.get("/perfil/bloqueoservi.mobileconfig")).status == 401
            shared = await client.get("/perfil/bloqueoservi.mobileconfig?k=clave-de-prueba")
            assert shared.status == 200
            raw_shared = await shared.read()
            body_shared = plistlib.loads(raw_shared)
            dns = [
                p["DNSSettings"] for p in body_shared["PayloadContent"] if p.get("DNSSettings")
            ][0]
            # el mismo DoH para todos y sin rastro de ningun token
            assert dns["DNSServerURLs"] == ["https://app.ejemplo.com/dns-query"]
            assert token not in raw_shared.decode()
            assert b"dev-" not in raw_shared

            short = await client.get("/config")
            assert short.status == 200
            assert short.headers["Content-Type"].startswith("application/x-apple-aspen-config")
            assert b"https://app.ejemplo.com/dns-query" in await short.read()

            # Con el perfil comun, este equipo entra por IP, no por token.
            ip_nueva = "203.0.113.55"
            otra = "203.0.113.56"
            comun = "app.ejemplo.com"

            def resuelto(nombre: str, desde: int) -> bool:
                """Si la consulta llego al resolutor de verdad o la corto el filtro."""
                return any(c.rstrip(".") == nombre for c in upstream.calls[desde:])

            # /activar es la pantalla que ve el movil: el generador de codigo,
            # sin pedir ninguna referencia.
            pantalla = await client.get("/activar", headers={"X-Forwarded-For": ip_nueva})
            cuerpo = await pantalla.text()
            assert pantalla.status == 200
            assert "Generar nuevo c" in cuerpo
            assert "Identifica tu" not in cuerpo
            # el movil se genera su codigo, como en la web antigua, y lo registra
            codigo_movil = "305911"
            registrado = await client.post(
                "/api/register",
                json={"code": codigo_movil},
                headers={"X-Forwarded-For": ip_nueva},
            )
            assert registrado.status == 200
            assert (await registrado.json())["ip"] == ip_nueva
            # el panel lo ve pendiente, con su IP, listo para que lo autorices
            panel = await (await client.get("/panel?k=clave-de-prueba")).text()
            assert codigo_movil in panel
            assert ip_nueva in panel

            # tú lo autorizas: ese telefono ya tiene salida
            ok = await client.post(
                "/api/admin/ok",
                json={"codigo": codigo_movil, "horas": 6},
                headers={"X-Admin-Key": "clave-de-prueba"},
            )
            assert ok.status == 200
            cuerpo_ok = await ok.json()
            assert cuerpo_ok["ip"] == ip_nueva
            assert cuerpo_ok["token"] == ""
            marca = len(upstream.calls)
            assert await doh("instagram.com", comun, "A", ip_nueva) == int(RCODE.NOERROR)
            assert resuelto("instagram.com", marca)
            # y el movil lo ve activo en su pantalla
            activa = await client.get("/activar", headers={"X-Forwarded-For": ip_nueva})
            assert "ACTIVADO" in await activa.text()
            # los tres vetados ni se mueven
            marca = len(upstream.calls)
            assert await doh("books.apple.com", comun, "A", ip_nueva) == int(RCODE.NXDOMAIN)
            assert not any("apple" in c for c in upstream.calls[marca:])
            # lo dejamos como estaba para seguir probando el canje
            await client.post(
                f"/api/admin/ip/{ip_nueva}", headers={"X-Admin-Key": "clave-de-prueba"}
            )



            # --- antes del codigo: solo el servicio ---
            marca = len(upstream.calls)
            assert await doh("youtube.com", comun, "A", ip_nueva) == int(RCODE.NOERROR)
            assert not resuelto("youtube.com", marca)
            assert await doh("t.me", comun, "A", ip_nueva) == int(RCODE.NOERROR)
            assert not resuelto("t.me", marca)
            # Instagram responde, pero no se resuelve: le llega la pantalla
            marca = len(upstream.calls)
            assert await doh("instagram.com", comun, "A", ip_nueva) == int(RCODE.NOERROR)
            assert not resuelto("instagram.com", marca)
            # y los tres vetados ni se intentan
            marca = len(upstream.calls)
            assert await doh("books.apple.com", comun, "A", ip_nueva) == int(RCODE.NXDOMAIN)
            assert await doh("itunes.apple.com", comun, "A", ip_nueva) == int(RCODE.NXDOMAIN)
            assert not any("apple" in c for c in upstream.calls[marca:])

            # el generador da un codigo y el movil lo canjea
            hecho = await client.post(
                "/api/admin/generar",
                json={"horas": 12},
                headers={"X-Admin-Key": "clave-de-prueba"},
            )
            codigo = (await hecho.json())["codigos"][0]["id"]
            canje = await client.post(
                "/api/canjear",
                json={"codigo": codigo},
                headers={"X-Forwarded-For": ip_nueva},
            )
            assert canje.status == 200
            assert (await canje.json())["horas"] == 12
            assert (await canje.json())["ip"] == ip_nueva

            # --- tras el codigo: sale todo menos los tres ---
            marca = len(upstream.calls)
            assert await doh("instagram.com", comun, "A", ip_nueva) == int(RCODE.NOERROR)
            assert resuelto("instagram.com", marca)
            assert await doh("www.netflix.com", comun, "A", ip_nueva) == int(RCODE.NOERROR)
            assert resuelto("www.netflix.com", marca)
            marca = len(upstream.calls)
            assert await doh("books.apple.com", comun, "A", ip_nueva) == int(RCODE.NXDOMAIN)
            assert await doh("itunes.apple.com", comun, "A", ip_nueva) == int(RCODE.NXDOMAIN)
            assert await doh("p01-contactsync.icloud.com", comun, "A", ip_nueva) == int(
                RCODE.NXDOMAIN
            )
            assert not any("apple" in c for c in upstream.calls[marca:])

            # otra IP distinta sigue en el estado de espera
            marca = len(upstream.calls)
            assert await doh("instagram.com", comun, "A", otra) == int(RCODE.NOERROR)
            assert not resuelto("instagram.com", marca)
            # y el mismo codigo no vale dos veces
            repetido = await client.post(
                "/api/canjear", json={"codigo": codigo}, headers={"X-Forwarded-For": otra}
            )
            assert repetido.status == 403

            # el panel ve el acceso y lo deja quitar
            panel_accesos = await (await client.get("/panel?k=clave-de-prueba")).text()
            assert ip_nueva in panel_accesos
            assert "ACTIVO" in panel_accesos
            assert (await client.post(f"/api/admin/ip/{ip_nueva}")).status == 401
            cortado = await client.post(
                f"/api/admin/ip/{ip_nueva}", headers={"X-Admin-Key": "clave-de-prueba"}
            )
            assert cortado.status == 200
            # tras revocar, ese telefono vuelve al estado de espera
            marca = len(upstream.calls)
            assert await doh("instagram.com", comun, "A", ip_nueva) == int(RCODE.NOERROR)
            assert not resuelto("instagram.com", marca)
            marca = len(upstream.calls)
            assert await doh("youtube.com", comun, "A", ip_nueva) == int(RCODE.NOERROR)
            assert not resuelto("youtube.com", marca)
            # y la revocacion sobrevive a un reinicio del servicio
            assert store.mode_for(None, ip_nueva) == MODE_STRICT
            assert Store(config.state_file).mode_for(None, ip_nueva) == MODE_STRICT

            # Con el perfil comun la IP es la identidad, asi que no se puede
            # suplantar: si hay Cloudflare delante manda CF-Connecting-IP, que
            # Cloudflare sobrescribe, y no el X-Forwarded-For del cliente.
            generado = await client.post(
                "/api/admin/generar",
                json={"horas": 2},
                headers={"X-Admin-Key": "clave-de-prueba"},
            )
            codigo2 = (await generado.json())["codigos"][0]["id"]
            real = "198.51.100.9"
            await client.post(
                "/api/canjear",
                json={"codigo": codigo2},
                headers={"CF-Connecting-IP": real, "X-Forwarded-For": "10.0.0.9"},
            )
            assert store.mode_for(None, real) == MODE_UNLOCKED
            # el valor que manda el cliente no abre nada por su cuenta
            assert store.mode_for(None, "10.0.0.9") == MODE_STRICT
            await client.post(f"/api/admin/ip/{real}", headers={"X-Admin-Key": "clave-de-prueba"})

            unknown = await client.get("/activar/000000000000")
            assert "no esta registrado" in await unknown.text()

        finally:
            await client.close()


def test_codes():
    """El movil genera el codigo, el administrador lo activa y caduca solo."""
    with tempfile.TemporaryDirectory() as directory:
        codes = Codes(os.path.join(directory, "codes.json"))

        assert not codes.is_valid("12345")
        assert not codes.is_valid("abcdef")
        assert codes.is_valid("000000")
        assert codes.is_valid(" 483920 ")
        try:
            codes.register("12")
            raise AssertionError("deberia rechazar un codigo corto")
        except ValueError:
            pass

        # El movil lo registra; nace pendiente.
        codes.register("483920", "aabbccddeeff", "203.0.113.9")
        entry = codes.get("483920")
        assert entry["active"] is False and entry["pending"] is True
        assert entry["token"] == "aabbccddeeff" and entry["ip"] == "203.0.113.9"
        assert entry["expires_at"] == 0

        # Registrar dos veces el mismo codigo no lo duplica ni lo reactiva.
        codes.register("483920")
        assert len(codes.list()) == 1

        # El administrador lo activa con una ventana de 2 horas.
        codes.activate("483920", 2, "panel")
        entry = codes.get("483920")
        assert entry["active"] is True and entry["pending"] is False
        assert entry["activated_by"] == "panel"
        assert 7100 < entry["expires_at"] - time.time() < 7300

        # Caduca solo, sin que nadie lo toque: se adelanta el reloj en el fichero.
        codes.activate("483920", 1, "panel")
        codes._codes["483920"]["expires_at"] = int(time.time()) - 10
        codes._write()
        entry = codes.get("483920")
        assert entry["active"] is False and entry["vencido"] is True
        assert entry["pending"] is True
        assert entry["expires_at"] == 0

        # Revocar lo deja pendiente otra vez.
        codes.activate("483920", 5, "panel")
        assert codes.revoke("483920") is True
        entry = codes.get("483920")
        assert entry["active"] is False and entry["vencido"] is False
        assert entry["activated_by"] == "" and entry["expires_at"] == 0

        assert codes.get("999999") is None
        assert codes.activate("999999", 1) is None
        assert codes.revoke("999999") is False

        # Sobrevive a reiniciar el servicio: se relee del fichero.
        reopened = Codes(os.path.join(directory, "codes.json"))
        assert [c["id"] for c in reopened.list()] == ["483920"]

        # No crece sin limite.
        for number in range(600):
            codes.register(f"{number:06d}")
        codes.prune(keep=500)
        assert len(Codes(os.path.join(directory, "codes.json")).list()) == 500
        # El mas antiguo es el que se va, y 483920 es de los mas viejos.
        assert "483920" not in [c["id"] for c in Codes(
            os.path.join(directory, "codes.json")
        ).list()]


def test_code_generator():
    """El administrador genera codigos y el movil los canjea una sola vez."""
    with tempfile.TemporaryDirectory() as directory:
        codes = Codes(os.path.join(directory, "codes.json"))

        made = codes.generate(6, valid_days=10)
        assert codes.is_valid(made["id"])
        assert made["origen"] == "panel"
        assert made["horas"] == 6
        assert made["active"] is False and made["usado_at"] == 0
        assert 864000 - 5 < made["valido_hasta"] - time.time() < 864000 + 5

        # El movil lo canjea y recibe las horas acordadas
        hours, entry = codes.redeem(made["id"], "aabbccddeeff", "203.0.113.9")
        assert hours == 6 and entry is not None
        assert entry["token"] == "aabbccddeeff" and entry["ip"] == "203.0.113.9"

        # No se puede canjear dos veces
        assert codes.redeem(made["id"], "otro") == (0, None)
        # Ni un codigo que no existe
        assert codes.redeem("000000", "aabbccddeeff") == (0, None)
        # Ni uno que genero el propio movil: ese no se canjea, se autoriza
        codes.register("555444", "aabbccddeeff")
        assert codes.redeem("555444", "aabbccddeeff") == (0, None)

        # Caducado para canjear
        old = codes.generate(3, valid_days=1)
        codes._codes[old["id"]]["valido_hasta"] = int(time.time()) - 1
        codes._write()
        assert codes.redeem(old["id"], "aabbccddeeff") == (0, None)

        # Al activarlo queda marcado como usado y caduca solo
        codes.activate(made["id"], 6, "canje")
        entry = codes.get(made["id"])
        assert entry["active"] is True and entry["usado_at"] > 0
        assert entry["activated_by"] == "canje"
        codes._codes[made["id"]]["expires_at"] = int(time.time()) - 1
        codes._write()
        entry = codes.get(made["id"])
        assert entry["active"] is False and entry["vencido"] is True
        assert entry["origen"] == "panel"

        # Cada codigo generado es distinto
        ids = {codes.generate(2)["id"] for _ in range(20)}
        assert len(ids) == 20


def test_web():
    asyncio.run(web_scenario())


async def apikey_scenario():
    """Simula al servidor del cliente activando un codigo con su API key."""
    with tempfile.TemporaryDirectory() as directory:
        config = make_config(directory, captive_ip="203.0.113.7")
        upstream = FakeUpstream()
        parts = Components(config)
        parts.upstream = upstream
        parts.filter.upstream = upstream
        service = parts.service
        # un equipo antiguo, que se identifica por token
        device = parts.store.add("Recepcion")
        ip = "88.13.24.99"

        client = TestClient(TestServer(service.build_app()))
        await client.start_server()

        # la pagina genera el codigo y lo registra con la IP del movil
        code = "761204"
        generado = await client.post(
            "/api/register", json={"code": code}, headers={"X-Forwarded-For": ip}
        )
        assert generado.status == 200, await generado.text()
        assert (await generado.json())["active"] is False
        registro = parts.codes.get(code)
        assert registro is not None and registro["ip"] == ip

        # sin cabecera no entra
        r = await client.post("/api/v1/activar", json={"codigo": code})
        assert r.status == 401, await r.text()

        # con una clave falsa tampoco
        r = await client.post(
            "/api/v1/activar", json={"codigo": code}, headers={"X-API-Key": "bsk_live_inventada"}
        )
        assert r.status == 403, await r.text()

        # el administrador crea la clave para su servidor
        entrada, key = parts.api_keys.create("activar", "servidor unlockersserver")
        assert key.startswith("bsk_live_")

        # el fichero solo guarda el hash, nunca la clave
        crudo = json.loads(open(parts.api_keys.path, encoding="utf-8").read())
        assert key not in json.dumps(crudo)
        assert any(e["id"] == entrada["id"] for e in crudo["keys"])

        # no puede consultar si su permiso es solo activar
        r = await client.get(f"/api/v1/estado/{code}", headers={"X-API-Key": key})
        assert r.status == 403, await r.text()

        # si no, la deniega
        r = await client.post("/api/v1/activar", json={"codigo": "000000"}, headers={"X-API-Key": key})
        assert r.status == 404, await r.text()

        # y si no, tampoco puede revocar
        r = await client.post("/api/v1/revocar", json={"codigo": code}, headers={"X-API-Key": key})
        assert r.status == 403, await r.text()

        # ahora si, con el codigo tal cual lo teclea el usuario
        r = await client.post(
            "/api/v1/activar", json={"codigo": code, "horas": 48}, headers={"X-API-Key": key}
        )
        assert r.status == 200, await r.text()
        cuerpo = await r.json()
        assert cuerpo["ok"] and cuerpo["ip"] == ip
        assert cuerpo["hours"] == 48  # misma forma de respuesta que el panel
        assert cuerpo["unlocked_until"] > int(time.time())
        assert cuerpo["api_key"] == entrada["id"]

        # el movil ya sale: instagram resuelve
        wire = DNSRecord.question("instagram.com", "A").pack()
        r = await client.post(
            "/dns-query",
            data=wire,
            headers={"Host": config.portal_host, "X-Forwarded-For": ip,
                     "Content-Type": "application/dns-message"},
        )
        assert int(DNSRecord.parse(await r.read()).header.rcode) == 0

        # la clave queda auditada
        usados = parts.api_keys.list()[0]
        assert usados["uses"] >= 2 and usados["last_used_at"] > 0

        # con permiso de consultar, ahora si lee el estado
        _, key_consulta = parts.api_keys.create("consultar", "consulta")
        r = await client.get(f"/api/v1/estado/{code}", headers={"X-API-Key": key_consulta})
        assert r.status == 200, await r.text()
        estado = await r.json()
        assert estado["id"] == code
        assert estado["active"] is True and estado["activated_by"] == "api"
        assert estado["ip"] == ip

        # Un codigo puede tener token (equipo antiguo) E IP (perfil unico). Antes
        # solo se abria una de las dos: la API decia ok y el movil seguia igual.
        mixto = parts.codes.register("445566", token=device["token"], ip=ip)
        assert mixto["token"] == device["token"] and mixto["ip"] == ip
        r = await client.post(
            "/api/v1/activar", json={"codigo": "445566", "horas": 12}, headers={"X-API-Key": key}
        )
        assert r.status == 200, await r.text()
        cuerpo = await r.json()
        assert cuerpo["token"] == device["token"] and cuerpo["ip"] == ip
        assert len(cuerpo["abierto"]) == 2
        # las dos identidades quedan abiertas
        assert parts.store.mode(device["token"]) == MODE_UNLOCKED
        assert parts.store.mode_for("", ip) == MODE_UNLOCKED

        # revocar la clave corta el acceso al instante
        assert parts.api_keys.revoke(entrada["id"])
        r = await client.post(
            "/api/v1/activar", json={"codigo": code}, headers={"X-API-Key": key}
        )
        assert r.status == 403, await r.text()


def test_apikeys():
    asyncio.run(apikey_scenario())


TESTS = [
    test_rules,
    test_policy_lists,
    test_config_tokens,
    test_store_and_licenses,
    test_filter,
    test_profile,
    test_codes,
    test_code_generator,
    test_web,
    test_apikeys,
]


def main() -> int:
    failures = 0
    for test in TESTS:
        try:
            test()
            print(f"ok   {test.__name__}")
        except Exception as exc:
            failures += 1
            print(f"FAIL {test.__name__}: {type(exc).__name__}: {exc}")
            import traceback

            traceback.print_exc()
    print(f"\n{len(TESTS) - failures}/{len(TESTS)} pruebas correctas")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
