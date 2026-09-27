from __future__ import annotations

from dnslib import A, DNSHeader, DNSRecord, DNSQuestion, QTYPE, RCODE, RR, SOA

from .querylog import ALLOWED, BLOCKED, ERROR, QueryLog
from .rules import MODE_STRICT, Policy
from .store import Store
from .upstream import Upstream, UpstreamError

BLOCK_ZONE = "blocked.local."
BLOCK_SOA = SOA("ns.blocked.local.", "hostmaster.blocked.local.", (1, 3600, 600, 604800, 60))
SUPPORTED_QTYPES = {1, 2, 5, 12, 15, 16, 28, 33, 35, 43, 48, 65, 257}
SOA_TYPE = int(QTYPE.SOA)
A_TYPE = int(QTYPE.A)
AAAA_TYPE = int(QTYPE.AAAA)
CAPTIVE_TTL = 60


class Filter:
    """Aplica la politica a una consulta DNS y devuelve la respuesta en formato wire."""

    def __init__(
        self,
        policy: Policy,
        store: Store,
        upstream: Upstream,
        log: QueryLog,
        blocked_rcode: str = "nxdomain",
        captive_ip: str = "",
    ) -> None:
        self.policy = policy
        self.store = store
        self.upstream = upstream
        self.log = log
        self.blocked_rcode = RCODE.REFUSED if blocked_rcode.lower() == "refused" else RCODE.NXDOMAIN
        self.captive_ip = captive_ip.strip()
        self.counters = {"allowed": 0, "blocked": 0, "error": 0}

    def _reply_skeleton(self, request: DNSRecord, rcode: int) -> DNSRecord:
        header = DNSHeader(id=request.header.id, bitmap=request.header.bitmap)
        header.qr = 1
        header.opcode = request.header.opcode
        header.rd = 0
        header.cd = request.header.cd
        header.ra = 1
        header.aa = 0
        header.tc = 0
        header.rcode = rcode
        reply = DNSRecord(header=header)
        reply.questions = [DNSQuestion(str(request.q.qname), request.q.qtype)]
        return reply

    def blocked_reply(self, request: DNSRecord) -> bytes:
        reply = self._reply_skeleton(request, self.blocked_rcode)
        if int(self.blocked_rcode) == int(RCODE.NXDOMAIN):
            reply.add_auth(RR(BLOCK_ZONE, SOA_TYPE, rdata=BLOCK_SOA, ttl=60))
        return reply.pack()

    def captive_reply(self, request: DNSRecord) -> bytes | None:
        """Responde con la IP del portal para que el movil abra la pantalla.

        En vez de un NXDOMAIN seco, lo bloqueado apunta al portal de
        activacion: el iPhone abre el navegador y cae en la pagina del codigo.
        Para AAAA se contesta sin registros, que es un "no hay IPv6" normal,
        de modo que el cliente cae en el registro A.
        """
        if not self.captive_ip or int(request.q.qtype) not in (A_TYPE, AAAA_TYPE):
            return None
        reply = self._reply_skeleton(request, RCODE.NOERROR)
        if int(request.q.qtype) == A_TYPE:
            reply.add_answer(RR(str(request.q.qname), A_TYPE, rdata=A(self.captive_ip), ttl=CAPTIVE_TTL))
        return reply.pack()

    def error_reply(self, request: DNSRecord, rcode: int = RCODE.SERVFAIL) -> bytes:
        return self._reply_skeleton(request, rcode).pack()

    async def handle(self, wire: bytes, device: str | None, client_ip: str = "") -> bytes | None:
        try:
            request = DNSRecord.parse(wire)
        except Exception:
            return None

        if int(request.header.qr) == 1:
            return None

        if not request.questions:
            return self.error_reply(request, RCODE.FORMERR)

        question = request.q
        name = str(question.qname).lower().rstrip(".")
        qtype = int(question.qtype)
        qtype_name = _qtype_name(qtype)

        if device:
            self.store.note_ip(device, client_ip)

        if len(request.questions) > 1:
            return self.error_reply(request, RCODE.FORMERR)

        if qtype not in SUPPORTED_QTYPES:
            self.log.record(ERROR, name, qtype_name, "tipo no admitido", device or "-", MODE_STRICT)
            return self.blocked_reply(request)

        # El modo sale del token si lo hay (perfil por equipo) y, si no, de la IP
        # (perfil unico para todos). Sin ninguno de los dos, estado de espera.
        mode = self.store.mode_for(device, client_ip)
        if client_ip and not device:
            self.store.note_ip_seen(client_ip)

        denied = self.policy.check_qtype(qtype_name)
        if denied is not None:
            self._count(BLOCKED)
            self.log.record(BLOCKED, name, qtype_name, denied.reason, device or "-", mode)
            if qtype == AAAA_TYPE:
                return self._reply_skeleton(request, RCODE.NOERROR).pack()
            return self.blocked_reply(request)

        decision = self.policy.decide(name, mode)
        if not decision.allow:
            self._count(BLOCKED)
            self.log.record(BLOCKED, name, qtype_name, decision.reason, device or "-", mode)
            # lo permanente no se arregla autorizando, asi que no lleva al portal
            if not decision.permanent:
                reply = self.captive_reply(request)
                if reply is not None:
                    return reply
            return self.blocked_reply(request)

        self._count(ALLOWED)
        self.store.touch(device)
        try:
            return await self.upstream.resolve(wire)
        except UpstreamError as exc:
            self._count(ERROR)
            self.log.record(ERROR, name, qtype_name, f"upstream: {exc}", device or "-", mode)
            return self.error_reply(request, RCODE.SERVFAIL)

    def _count(self, kind: str) -> None:
        self.counters[kind] = self.counters.get(kind, 0) + 1

    def stats(self) -> dict[str, int]:
        data = dict(self.counters)
        data.update(self.upstream.stats())
        return data


def _qtype_name(qtype: int) -> str:
    try:
        return QTYPE[qtype]
    except Exception:
        return str(qtype)
