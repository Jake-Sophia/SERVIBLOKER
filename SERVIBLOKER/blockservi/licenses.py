from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class LicenseResult:
    ok: bool
    reason: str
    label: str = ""
    expires_at: int = 0


class Licenses:
    """Lee el mismo licenses.json que usa el panel PHP de licencias."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._mtime: float = -1.0
        self._entries: dict[str, dict] = {}
        self.reload()

    def reload(self) -> None:
        with self._lock:
            try:
                mtime = os.path.getmtime(self.path)
            except FileNotFoundError:
                self._mtime = -1.0
                self._entries = {}
                return
            if mtime == self._mtime:
                return
            try:
                with open(self.path, "r", encoding="utf-8") as handle:
                    raw = json.load(handle)
            except (json.JSONDecodeError, OSError):
                return
            self._entries = raw if isinstance(raw, dict) else {}
            self._mtime = mtime

    def check(self, code: str, now: int | None = None) -> LicenseResult:
        now = int(time.time()) if now is None else now
        code = code.strip().upper()
        if not code:
            return LicenseResult(False, "codigo vacio")
        self.reload()
        with self._lock:
            entry = self._entries.get(code)
        if not isinstance(entry, dict):
            return LicenseResult(False, "codigo_no_encontrado")
        if entry.get("status") == "revoked":
            expires_at = int(entry.get("expires_at", 0))
            return LicenseResult(False, "licencia_revocada", expires_at=expires_at)
        expires_at = int(entry.get("expires_at", 0))
        if expires_at and expires_at < now:
            return LicenseResult(False, "licencia_vencida", expires_at=expires_at)
        return LicenseResult(True, "ok", str(entry.get("label", "")), expires_at)

    def count(self) -> int:
        self.reload()
        with self._lock:
            return len(self._entries)

    def inventory(self, now: int | None = None) -> list[dict]:
        """Licencias utilizables, para elegir una al autorizar un equipo."""
        now = int(time.time()) if now is None else now
        self.reload()
        with self._lock:
            entries = [(code, dict(entry)) for code, entry in self._entries.items()]
        rows: list[dict] = []
        for code, entry in entries:
            if not isinstance(entry, dict):
                continue
            expires_at = int(entry.get("expires_at", 0))
            revoked = entry.get("status") == "revoked"
            rows.append(
                {
                    "codigo": code,
                    "label": str(entry.get("label", "")),
                    "expires_at": expires_at,
                    "usada": revoked or bool(expires_at and expires_at < now),
                }
            )
        return sorted(rows, key=lambda row: row["codigo"])
