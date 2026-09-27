from __future__ import annotations

import asyncio
import random
import time
from typing import Any

import aiohttp
from dnslib import DNSRecord, QTYPE, RCODE

DOH_CONTENT_TYPE = "application/dns-message"
CACHEABLE_RCODES = {int(RCODE.NOERROR), int(RCODE.NXDOMAIN)}


class UpstreamError(Exception):
    pass


class Upstream:
    """Reenvia consultas a resolventes externos, con cache corta y sin repetir consultas."""

    def __init__(
        self,
        doh_endpoints: tuple[str, ...],
        udp_servers: tuple[str, ...],
        timeout: float = 5.0,
        cache_ttl: int = 300,
        cache_max: int = 20000,
        session: Any | None = None,
    ) -> None:
        self.doh_endpoints = tuple(endpoint.rstrip("/") for endpoint in doh_endpoints)
        self.udp_servers = udp_servers
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.cache_max = cache_max
        self._session = session
        self._cache: dict[tuple, tuple[float, bytes]] = {}
        self._inflight: dict[tuple, "asyncio.Future[bytes]"] = {}
        self.hits = 0
        self.misses = 0

    def set_session(self, session: Any) -> None:
        self._session = session

    def stats(self) -> dict[str, int]:
        return {"hits": self.hits, "misses": self.misses, "cache": len(self._cache)}

    def cache_clear(self) -> None:
        self._cache.clear()

    def _key(self, request: DNSRecord) -> tuple:
        question = request.q
        name = str(question.qname).lower().rstrip(".")
        return (name, int(question.qtype), int(request.header.rd))

    def _cache_get(self, key: tuple) -> bytes | None:
        entry = self._cache.get(key)
        if entry is None:
            self.misses += 1
            return None
        expires, payload = entry
        if expires < time.monotonic():
            del self._cache[key]
            self.misses += 1
            return None
        self.hits += 1
        return payload

    def _cache_put(self, key: tuple, payload: bytes) -> None:
        try:
            rcode = int(DNSRecord.parse(payload).header.rcode)
        except Exception:
            return
        if rcode not in CACHEABLE_RCODES:
            return
        if len(self._cache) > self.cache_max:
            now = time.monotonic()
            expired = [item for item, value in self._cache.items() if value[0] < now]
            for item in expired:
                self._cache.pop(item, None)
            if len(self._cache) > self.cache_max:
                self._cache.clear()
        self._cache[key] = (time.monotonic() + self._cache_ttl_for(payload), payload)

    def _cache_ttl_for(self, payload: bytes) -> int:
        try:
            reply = DNSRecord.parse(payload)
        except Exception:
            return self.cache_ttl
        if int(reply.header.rcode) == int(RCODE.NXDOMAIN) or not reply.rr:
            for rr in reply.auth:
                if int(rr.rtype) == int(QTYPE.SOA):
                    try:
                        return max(30, int(rr.rdata.times[4]))
                    except Exception:
                        return 60
            return min(self.cache_ttl, 60)
        ttls = [int(rr.ttl) for rr in reply.rr if int(rr.ttl) > 0]
        if not ttls:
            return self.cache_ttl
        return max(1, min(ttls))

    async def resolve(self, wire: bytes) -> bytes:
        try:
            request = DNSRecord.parse(wire)
        except Exception as exc:
            raise UpstreamError(f"consulta invalida: {exc}") from exc
        if request.header.qr:
            raise UpstreamError("se recibio una respuesta en el servidor de consultas")

        key = self._key(request)
        cached = self._cache_get(key)
        if cached is not None:
            return self._rewrite_id(cached, request)

        existing = self._inflight.get(key)
        if existing is not None:
            payload = await asyncio.shield(existing)
            return self._rewrite_id(payload, request)

        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self._inflight[key] = future
        try:
            payload = await self._forward(request, wire)
        except BaseException as exc:
            if not future.done():
                future.set_exception(exc)
            raise
        finally:
            self._inflight.pop(key, None)
        if not future.done():
            future.set_result(payload)
        self._cache_put(key, payload)
        return self._rewrite_id(payload, request)

    @staticmethod
    def _rewrite_id(payload: bytes, request: DNSRecord) -> bytes:
        try:
            reply = DNSRecord.parse(payload)
        except Exception:
            return payload
        reply.header.id = request.header.id
        return reply.pack()

    async def _forward(self, request: DNSRecord, wire: bytes) -> bytes:
        order = list(self.doh_endpoints) + list(self.udp_servers)
        if not order:
            raise UpstreamError("no hay resolventes configurados")
        random.shuffle(order)
        errors: list[str] = []
        for endpoint in order:
            try:
                if endpoint.startswith("http"):
                    payload = await self._forward_doh(endpoint, wire)
                else:
                    payload = await self._forward_udp(endpoint, request)
                return payload
            except Exception as exc:
                errors.append(f"{endpoint}: {exc}")
        raise UpstreamError(" | ".join(errors))

    async def _forward_doh(self, endpoint: str, wire: bytes) -> bytes:
        if self._session is None:
            raise UpstreamError("sin sesion HTTP")
        async with self._session.post(
            endpoint,
            data=wire,
            headers={"Content-Type": DOH_CONTENT_TYPE, "Accept": DOH_CONTENT_TYPE},
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        ) as response:
            if response.status != 200:
                raise UpstreamError(f"HTTP {response.status}")
            body = await response.read()
        self._check_matching(body, wire)
        return body

    async def _forward_udp(self, server: str, request: DNSRecord) -> bytes:
        query = DNSRecord.question(str(request.q.qname), request.q.qtype)
        query.header.rd = 1
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            _UdpProtocolFactory(loop), remote_addr=(server, 53)
        )
        try:
            transport.sendto(query.pack())
            payload = await asyncio.wait_for(protocol.result(), timeout=self.timeout)
        finally:
            transport.close()
        if payload is None:
            raise UpstreamError("sin respuesta")
        reply = DNSRecord.parse(payload)
        if not reply.header.qr:
            raise UpstreamError("respuesta invalida")
        reply.header.id = request.header.id
        return reply.pack()

    @staticmethod
    def _check_matching(body: bytes, query: bytes) -> None:
        reply = DNSRecord.parse(body)
        original = DNSRecord.parse(query)
        if not reply.header.qr:
            raise UpstreamError("respuesta sin QR")
        if str(reply.q.qname).lower() != str(original.q.qname).lower():
            raise UpstreamError("la respuesta no coincide con la consulta")
        if int(reply.q.qtype) != int(original.q.qtype):
            raise UpstreamError("el tipo de la respuesta no coincide")


class _UdpProtocolFactory:
    """Adaptador minimo para awaitear una datagrama unica con asyncio."""

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._future: asyncio.Future = loop.create_future()

    def __call__(self) -> "_UdpProtocol":
        return _UdpProtocol(self._future)

    def result(self) -> asyncio.Future:
        return self._future


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future) -> None:
        self._future = future

    def datagram_received(self, data: bytes, addr: Any) -> None:
        if not self._future.done():
            self._future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(UpstreamError(str(exc)))

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is not None and not self._future.done():
            self._future.set_exception(UpstreamError(str(exc)))
