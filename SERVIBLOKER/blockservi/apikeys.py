from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import Any

# Permisos. "*" da todo, que es lo que lleva la clave de administracion.
SCOPE_ACTIVAR = "activar"
SCOPE_CONSULTAR = "consultar"
SCOPE_REVOCAR = "revocar"
SCOPES = (SCOPE_ACTIVAR, SCOPE_CONSULTAR, SCOPE_REVOCAR)

PREFIX = "bsk_live_"
KEY_BYTES = 24


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class ApiKeys:
    """Claves para que otro servidor pueda activar codigos.

    A diferencia de la clave de administracion, estas se pueden limitar a un
    permiso concreto, revocar sin tocar el panel, y auditarlas. De la clave solo
    se guarda el hash: si alguien lee el fichero no puede usarla ni verla.

    La clave se acepta solo por cabecera, nunca en la query, para que no acabe
    en los registros de acceso de Caddy.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._mtime: float = -1.0
        self._entries: list[dict[str, Any]] = []
        self.reload()

    def reload(self) -> None:
        with self._lock:
            try:
                mtime = os.path.getmtime(self.path)
            except FileNotFoundError:
                self._mtime = -1.0
                self._entries = []
                return
            if mtime == self._mtime:
                return
            try:
                with open(self.path, "r", encoding="utf-8") as handle:
                    raw = json.load(handle)
            except (json.JSONDecodeError, OSError):
                return
            entries = raw.get("keys", []) if isinstance(raw, dict) else []
            if not isinstance(entries, list):
                entries = []
            self._entries = [e for e in entries if isinstance(e, dict)]
            self._mtime = mtime

    def _write(self) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, mode=0o700, exist_ok=True)
        temp = f"{self.path}.tmp"
        with open(temp, "w", encoding="utf-8") as handle:
            json.dump({"keys": self._entries}, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, self.path)
        os.chmod(self.path, 0o600)
        self._mtime = os.path.getmtime(self.path)

    def create(self, scope: str = SCOPE_ACTIVAR, note: str = "") -> tuple[dict[str, Any], str]:
        """Crea una clave y la devuelve en claro. Solo se ve este momento."""
        if scope != "*" and scope not in SCOPES:
            raise ValueError(f"permiso desconocido: {scope}")
        key = PREFIX + secrets.token_urlsafe(KEY_BYTES)
        with self._lock:
            self.reload()
            entry = {
                "id": secrets.token_hex(6),
                "scope": scope,
                "note": str(note or "")[:120],
                "hash": _hash(key),
                "created_at": int(time.time()),
                "last_used_at": 0,
                "uses": 0,
            }
            self._entries.append(entry)
            self._write()
            return dict(entry), key

    def verify(self, key: str, scope: str = "") -> dict[str, Any] | None:
        """Comprueba la clave y, si se pide, que tenga ese permiso.

        Se recorren todas las claves comparando el hash con compare_digest, sin
        salir antes en el primer fallo, para no filtrar por tiempo cual era.
        """
        key = str(key or "").strip()
        if not key:
            return None
        wanted = _hash(key)
        found: dict[str, Any] | None = None
        with self._lock:
            self.reload()
            for entry in self._entries:
                if hmac.compare_digest(str(entry.get("hash", "")), wanted):
                    found = entry
            if found is None:
                return None
            if found.get("revocado"):
                return None
            if scope and scope not in (found.get("scope"), "*"):
                return None
            found["uses"] = int(found.get("uses", 0)) + 1
            found["last_used_at"] = int(time.time())
            self._write()
            return dict(found)

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            self.reload()
            return sorted(
                (dict(e) for e in self._entries),
                key=lambda e: int(e.get("created_at", 0)),
                reverse=True,
            )

    def revoke(self, key_id: str) -> bool:
        with self._lock:
            self.reload()
            for entry in self._entries:
                if entry.get("id") == key_id:
                    entry["revocado"] = True
                    entry["revoked_at"] = int(time.time())
                    self._write()
                    return True
        return False
