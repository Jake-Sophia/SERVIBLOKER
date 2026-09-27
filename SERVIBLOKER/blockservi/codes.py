"""Registro global de codigos de activacion.

El codigo lo genera la propia pagina que ve el movil, lo registra aqui y lo
ensea al administrador. Cuando este lo activa, el codigo pasa a valer y se
guarda cuando caduca, igual que hacia el proyecto antiguo.

Se guarda aparte de devices.json porque son dos cosas distintas: aqui hay
codigos sueltos, alla hay equipos.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from typing import Any

CODE_RE = re.compile(r"^[0-9]{6}$")
CODE_BYTES = 8


class Codes:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._mtime: float = -1.0
        self._codes: dict[str, dict[str, Any]] = {}
        self.reload()

    def reload(self) -> None:
        with self._lock:
            try:
                mtime = os.path.getmtime(self.path)
            except FileNotFoundError:
                self._mtime = -1.0
                self._codes = {}
                return
            if mtime == self._mtime:
                return
            try:
                with open(self.path, "r", encoding="utf-8") as handle:
                    raw = json.load(handle)
            except (json.JSONDecodeError, OSError):
                return
            codes = raw.get("codes", {}) if isinstance(raw, dict) else {}
            if not isinstance(codes, dict):
                codes = {}
            self._codes = {
                str(code): dict(entry)
                for code, entry in codes.items()
                if isinstance(entry, dict)
            }
            self._mtime = mtime

    def _write(self) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, mode=0o700, exist_ok=True)
        temp = f"{self.path}.tmp"
        payload = json.dumps({"codes": self._codes}, indent=2, sort_keys=True)
        with open(temp, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, self.path)
        os.chmod(self.path, 0o600)
        self._mtime = os.path.getmtime(self.path)

    @staticmethod
    def is_valid(code: str) -> bool:
        return bool(CODE_RE.match(str(code or "").strip()))

    def generate(self, hours: int, valid_days: int = 30) -> dict[str, Any]:
        """Crea un codigo sueltas, sin equipo asociado, para entregarlo a alguien.

        Sirve para dar acceso completo a un telefono sin que tenga que pedir nada:
        el administrador genera el codigo, se lo pasa y el movil lo canjea.
        """
        hours = max(1, min(int(hours), 24 * 90))
        valid_days = max(1, min(int(valid_days), 365))
        now = int(time.time())
        with self._lock:
            self.reload()
            for _ in range(CODE_BYTES * 8):
                code = f"{secrets.randbelow(1000000):06d}"
                if code not in self._codes:
                    break
            else:  # pragma: no cover - 10^6 espacios y solo seis digitos
                raise RuntimeError("no queda ningun codigo libre")
            entry = {
                "id": code,
                "active": False,
                "created_at": now,
                "activated_at": 0,
                "activated_by": "",
                "expires_at": 0,
                "token": "",
                "ip": "",
                "visto": now,
                "horas": hours,
                "valido_hasta": now + valid_days * 86400,
                "usado_at": 0,
                "origen": "panel",
            }
            self._codes[code] = entry
            self._write()
            return self._view(dict(entry))

    def redeem(self, code: str, token: str, ip: str = "") -> tuple[int, dict[str, Any] | None]:
        """Canjea un codigo de los generados por el administrador.

        Devuelve las horas que concede y la entrada, o None si el codigo no
        sirve: inexistente, ya usado, caducado o generado por un movil.
        """
        code = str(code or "").strip()
        with self._lock:
            self.reload()
            entry = self._codes.get(code)
            if entry is None or not entry.get("origen") == "panel":
                return 0, None
            now = int(time.time())
            if entry.get("usado_at"):
                return 0, None
            if int(entry.get("valido_hasta", 0)) and int(entry["valido_hasta"]) < now:
                return 0, None
            entry["token"] = token
            if ip:
                entry["ip"] = ip
            entry["visto"] = now
            # Se marca aqui, dentro del candado, para que dos telefonos no puedan
            # canjear el mismo codigo a la vez.
            entry["usado_at"] = now
            self._write()
            return int(entry.get("horas", 24)), dict(entry)

    def register(self, code: str, token: str = "", ip: str = "") -> dict[str, Any]:
        """Da de alta el codigo que ha generado el movil. Es idempotente."""
        code = str(code or "").strip()
        if not self.is_valid(code):
            raise ValueError("el codigo deben ser 6 digitos")
        with self._lock:
            self.reload()
            entry = self._codes.get(code)
            now = int(time.time())
            if entry is None:
                entry = {
                    "id": code,
                    "active": False,
                    "created_at": now,
                    "activated_at": 0,
                    "activated_by": "",
                    "expires_at": 0,
                    "token": "",
                    "ip": "",
                }
                self._codes[code] = entry
            if token:
                entry["token"] = token
            if ip:
                entry["ip"] = ip
            entry["visto"] = now
            self._write()
            return dict(entry)

    def bind(self, code: str, token: str) -> bool:
        with self._lock:
            self.reload()
            entry = self._codes.get(str(code or "").strip())
            if entry is None:
                return False
            entry["token"] = token
            self._write()
            return True

    def activate(self, code: str, hours: int, by: str = "panel") -> dict[str, Any] | None:
        with self._lock:
            self.reload()
            entry = self._codes.get(str(code or "").strip())
            if entry is None:
                return None
            now = int(time.time())
            entry["active"] = True
            entry["activated_at"] = now
            entry["activated_by"] = str(by)[:40]
            entry["expires_at"] = now + max(1, int(hours)) * 3600
            entry["horas"] = int(hours)
            entry["usado_at"] = now
            self._write()
            return dict(entry)

    def revoke(self, code: str) -> bool:
        with self._lock:
            self.reload()
            entry = self._codes.get(str(code or "").strip())
            if entry is None:
                return False
            entry["active"] = False
            entry["activated_at"] = 0
            entry["activated_by"] = ""
            entry["expires_at"] = 0
            self._write()
            return True

    def get(self, code: str) -> dict[str, Any] | None:
        with self._lock:
            self.reload()
            entry = self._codes.get(str(code or "").strip())
            return self._view(dict(entry)) if entry else None

    def _view(self, entry: dict[str, Any]) -> dict[str, Any]:
        now = int(time.time())
        expires_at = int(entry.get("expires_at", 0))
        active = bool(entry.get("active")) and expires_at > now
        return {
            "id": str(entry.get("id", "")),
            "active": active,
            "pending": not active,
            "created_at": int(entry.get("created_at", 0)),
            "activated_at": int(entry.get("activated_at", 0)),
            "activated_by": str(entry.get("activated_by", "")),
            "expires_at": expires_at if active else 0,
            "vencido": bool(entry.get("active")) and expires_at <= now,
            "horas": int(entry.get("horas", 0)),
            "valido_hasta": int(entry.get("valido_hasta", 0)),
            "usado_at": int(entry.get("usado_at", 0)),
            "origen": str(entry.get("origen", "movil")),
            "token": str(entry.get("token", "")),
            "ip": str(entry.get("ip", "")),
            "label": str(entry.get("label", "")),
        }

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            self.reload()
            views = [self._view(dict(entry)) for entry in self._codes.values()]
        return sorted(views, key=lambda row: row["created_at"], reverse=True)

    def prune(self, keep: int = 500) -> None:
        """Deja solo los codigos recientes para que el fichero no crezca sin fin."""
        with self._lock:
            self.reload()
            if len(self._codes) <= keep:
                return
            ordered = sorted(self._codes.items(), key=lambda item: int(item[1].get("visto", 0)))
            for code, _ in ordered[: len(self._codes) - keep]:
                del self._codes[code]
            self._write()
