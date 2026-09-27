from __future__ import annotations

import asyncio
from typing import Any

from dnslib import DNSRecord
from dnslib.server import DNSHandler, DNSServer

UDP_MAX = 512


class _UdpHandler(DNSHandler):
    """Recorta las respuestas grandes para que el cliente reintente por TCP."""

    udplen = UDP_MAX


class PlainBridge:
    """Sirve DNS en claro (UDP y TCP) para el propio VPS y para pruebas.

    El dispositivo se deduce de la IP de origen mediante device_map, porque en
    una red movil la IP no es estable. Sin entrada, el cliente usa el modo estricto.
    """

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        dns_filter: Any,
        device_map: dict[str, str],
        timeout: float = 10.0,
    ) -> None:
        self.loop = loop
        self.filter = dns_filter
        self.device_map = device_map
        self.timeout = timeout

    def device_for(self, handler: Any) -> str | None:
        client = getattr(handler, "client_address", None)
        if not client:
            return None
        return self.device_map.get(str(client[0]))

    def client_ip(self, handler: Any) -> str:
        client = getattr(handler, "client_address", None)
        if not client:
            return ""
        return str(client[0])

    def resolve(self, record: DNSRecord, handler: Any = None) -> DNSRecord:
        device = self.device_for(handler)
        future = asyncio.run_coroutine_threadsafe(
            self.filter.handle(record.pack(), device, self.client_ip(handler)), self.loop
        )
        try:
            wire = future.result(timeout=self.timeout)
        except Exception:
            future.cancel()
            return DNSRecord.parse(self.filter.error_reply(record))
        if not wire:
            return DNSRecord.parse(self.filter.error_reply(record))
        return DNSRecord.parse(wire)

    def start(self, host: str, port: int) -> list[DNSServer]:
        servers = [
            DNSServer(self, address=host, port=port, handler=_UdpHandler),
            DNSServer(self, address=host, port=port, tcp=True, handler=_UdpHandler),
        ]
        for server in servers:
            server.start_thread()
        return servers
