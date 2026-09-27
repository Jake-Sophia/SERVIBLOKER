from __future__ import annotations

import json
import os
import secrets
import threading
import time
from typing import Any

from .rules import MODE_STRICT, MODE_UNLOCKED

TOKEN_BYTES = 6
TOUCH_INTERVAL = 600
REQUEST_TTL = 12 * 3600
REQUEST_CODE_RANGE = 1000000


class Store:
    """Dispositivos conocidos y ventanas de acceso de 24 horas.

    El fichero se relee si cambia su mtime, de forma que las altas o revocaciones
    hechas desde el panel en PHP o desde la CLI se aplican sin reiniciar.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._mtime: float = -1.0
        self._devices: dict[str, dict[str, Any]] = {}
        # Acceso por IP, para cuando se instala un unico perfil en todos los
        # telefonos: al no haber token en el Host, el equipo se identifica por
        # la direccion desde la que consulta.
        self._ips: dict[str, dict[str, Any]] = {}
        self._dirty_touch: set[str] = set()
        self._last_touch_write = 0.0
        self.reload()

    def reload(self) -> None:
        with self._lock:
            try:
                mtime = os.path.getmtime(self.path)
            except FileNotFoundError:
                self._mtime = -1.0
                self._devices = {}
                self._ips = {}
                return
            if mtime == self._mtime:
                return
            try:
                with open(self.path, "r", encoding="utf-8") as handle:
                    raw = json.load(handle)
                devices = raw.get("devices", {}) if isinstance(raw, dict) else {}
                if not isinstance(devices, dict):
                    devices = {}
            except (json.JSONDecodeError, OSError):
                return
            self._devices = {
                str(token): dict(entry)
                for token, entry in devices.items()
                if isinstance(entry, dict)
            }
            ips = raw.get("ips", {}) if isinstance(raw, dict) else {}
            if not isinstance(ips, dict):
                ips = {}
            self._ips = {
                str(ip): dict(entry) for ip, entry in ips.items() if isinstance(entry, dict)
            }
            self._mtime = mtime

    def _write(self) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, mode=0o700, exist_ok=True)
        temp = f"{self.path}.tmp"
        payload = json.dumps({"devices": self._devices, "ips": self._ips}, indent=2, sort_keys=True)
        with open(temp, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, self.path)
        os.chmod(self.path, 0o600)
        self._mtime = os.path.getmtime(self.path)

    def _schedule_write(self) -> None:
        self._write()

    def new_token(self) -> str:
        with self._lock:
            while True:
                token = secrets.token_hex(TOKEN_BYTES)
                if token not in self._devices:
                    return token

    def add(self, label: str = "", code: str = "") -> dict[str, Any]:
        with self._lock:
            token = self.new_token()
            now = int(time.time())
            device = {
                "label": label.strip()[:80],
                "code": code.strip().upper()[:40],
                "created_at": now,
                "unlocked_until": 0,
                "unlock_count": 0,
                "last_seen": 0,
                "last_ip": "",
                "request_code": "",
                "requested_at": 0,
            }
            self._devices[token] = device
            self._schedule_write()
            return dict(device, token=token)

    def device(self, token: str) -> dict[str, Any] | None:
        self.reload()
        with self._lock:
            device = self._devices.get(token)
            return dict(device, token=token) if device else None

    def mode(self, token: str | None) -> str:
        if not token:
            return MODE_STRICT
        self.reload()
        with self._lock:
            device = self._devices.get(token)
            if not device:
                return MODE_STRICT
            if int(device.get("unlocked_until", 0)) > int(time.time()):
                return MODE_UNLOCKED
            return MODE_STRICT

    def unlock(self, token: str, code: str, hours: int) -> dict[str, Any]:
        with self._lock:
            self.reload()
            device = self._devices.get(token)
            if device is None:
                raise KeyError(token)
            now = int(time.time())
            device["unlocked_until"] = now + max(1, int(hours)) * 3600
            device["unlock_count"] = int(device.get("unlock_count", 0)) + 1
            if code:
                device["code"] = code.strip().upper()[:40]
            device["last_unlock_at"] = now
            self._schedule_write()
            return dict(device, token=token)

    def mode_for(self, token: str | None, ip: str = "") -> str:
        """Modo efectivo de quien consulta.

        Con perfil por equipo manda el token. Con un unico perfil para todos no
        hay token en el Host, asi que manda la IP: si esa direccion tiene una
        ventana de acceso abierta, entra; si no, se queda en el estado de espera
        (solo la lista blanca).
        """
        if token:
            return self.mode(token)
        ip = str(ip or "")
        if ip:
            with self._lock:
                self.reload()
                entry = self._ips.get(ip)
                if entry and int(entry.get("unlocked_until", 0)) > int(time.time()):
                    return MODE_UNLOCKED
        return MODE_STRICT

    def unlock_ip(self, ip: str, code: str, hours: int) -> dict[str, Any]:
        """Abre la ventana de acceso de una direccion IP.

        Es lo que usa el canje de codigo cuando el telefono lleva el perfil
        compartido: sin token no hay contra que atar la ventana.
        """
        ip = str(ip or "").strip()
        if not ip:
            raise KeyError("sin ip")
        with self._lock:
            self.reload()
            now = int(time.time())
            entry = self._ips.setdefault(ip, {"unlocked_until": 0, "unlock_count": 0})
            entry["unlocked_until"] = now + max(1, int(hours)) * 3600
            entry["unlock_count"] = int(entry.get("unlock_count", 0)) + 1
            entry["last_unlock_at"] = now
            entry["last_seen"] = now
            if code:
                entry["code"] = code.strip().upper()[:40]
            self._schedule_write()
            return dict(entry, ip=ip)

    def set_ip_unlocked_until(self, ip: str, timestamp: int) -> bool:
        ip = str(ip or "").strip()
        if not ip:
            return False
        with self._lock:
            self.reload()
            entry = self._ips.get(ip)
            if entry is None:
                if not timestamp:
                    return False
                entry = {"unlocked_until": 0, "unlock_count": 0}
                self._ips[ip] = entry
            entry["unlocked_until"] = int(timestamp)
            self._schedule_write()
            return True

    def note_ip_seen(self, ip: str) -> None:
        """Deja constancia de que esa IP ha consultado, para verla en el panel."""
        ip = str(ip or "").strip()
        if not ip:
            return
        with self._lock:
            self.reload()
            entry = self._ips.get(ip)
            if entry is None:
                return
            if int(entry.get("last_seen", 0)) > int(time.time()) - 300:
                return
            entry["last_seen"] = int(time.time())
            self._schedule_write()

    def ip_entry(self, ip: str) -> dict[str, Any] | None:
        with self._lock:
            self.reload()
            entry = self._ips.get(str(ip or ""))
            return dict(entry, ip=ip) if entry else None

    def ip_list(self) -> list[dict[str, Any]]:
        with self._lock:
            self.reload()
            now = int(time.time())
            rows = []
            for ip, entry in self._ips.items():
                until = int(entry.get("unlocked_until", 0))
                rows.append(
                    {
                        "ip": ip,
                        "unlocked_until": until,
                        "activo": until > now,
                        "unlock_count": int(entry.get("unlock_count", 0)),
                        "last_unlock_at": int(entry.get("last_unlock_at", 0)),
                        "last_seen": int(entry.get("last_seen", 0)),
                    }
                )
        return sorted(rows, key=lambda row: row["last_unlock_at"] or row["last_seen"], reverse=True)

    def set_unlocked_until(self, token: str, timestamp: int) -> dict[str, Any]:
        with self._lock:
            self.reload()
            device = self._devices.get(token)
            if device is None:
                raise KeyError(token)
            device["unlocked_until"] = int(timestamp)
            self._schedule_write()
            return dict(device, token=token)

    def delete(self, token: str) -> bool:
        with self._lock:
            self.reload()
            if token not in self._devices:
                return False
            del self._devices[token]
            self._schedule_write()
            return True

    # --- codigos que solicita el propio dispositivo -----------------------

    def _new_request_code(self) -> str:
        taken = {str(entry.get("request_code") or "") for entry in self._devices.values()}
        while True:
            code = f"{secrets.randbelow(REQUEST_CODE_RANGE):06d}"
            if code not in taken:
                return code

    def request(self, token: str) -> str:
        """Codigo de 6 digitos que el dispositivo ensena al administrador.

        Se reutiliza mientras siga vigente para que la pantalla no cambie de
        codigo mientras el empleado lo esta leyendo o comunicando.
        """
        with self._lock:
            self.reload()
            device = self._devices.get(token)
            if device is None:
                raise KeyError(token)
            now = int(time.time())
            current = str(device.get("request_code") or "")
            fresh = now - int(device.get("requested_at", 0)) < REQUEST_TTL
            if current and fresh:
                return current
            code = self._new_request_code()
            device["request_code"] = code
            device["requested_at"] = now
            self._schedule_write()
            return code

    def request_info(self, token: str) -> dict[str, Any]:
        """Lo que ve el movil: su codigo, su IP y el estado del acceso."""
        with self._lock:
            self.reload()
            device = self._devices.get(token)
            if device is None:
                raise KeyError(token)
            now = int(time.time())
            requested_at = int(device.get("requested_at", 0))
            code = str(device.get("request_code") or "")
            fresh = bool(code) and now - requested_at < REQUEST_TTL
            return {
                "token": token,
                "label": str(device.get("label") or ""),
                "codigo": code if fresh else "",
                "codigo_caduca": (requested_at + REQUEST_TTL) if fresh else 0,
                "ip": str(device.get("last_ip") or ""),
                "modo": self.mode(token),
                "visto": int(device.get("last_seen", 0)),
                "desbloqueado_hasta": int(device.get("unlocked_until", 0)),
            }

    def _ip_bucket(self, ip: str) -> dict[str, Any]:
        ip = str(ip or "").strip()
        if not ip:
            raise KeyError("sin ip")
        entry = self._ips.setdefault(ip, {"unlocked_until": 0, "unlock_count": 0})
        return entry

    def request_ip(self, ip: str, nuevo: bool = False) -> str:
        """Codigo de 6 digitos de un telefono con el perfil unico.

        Es el mismo que pide un equipo con token, pero identified por la IP: el
        movil no tiene token porque el perfil es el mismo para todos. Se
        reutiliza mientras siga vigente, para que el empleado vea siempre el
        mismo codigo mientras lo lee o se lo comunica.
        """
        with self._lock:
            self.reload()
            entry = self._ip_bucket(ip)
            now = int(time.time())
            current = str(entry.get("request_code") or "")
            fresh = now - int(entry.get("requested_at", 0)) < REQUEST_TTL
            if current and fresh and not nuevo:
                return current
            code = self._new_request_code()
            entry["request_code"] = code
            entry["requested_at"] = now
            self._schedule_write()
            return code

    def request_info_ip(self, ip: str) -> dict[str, Any]:
        """Lo que ve el movil con el perfil unico: su codigo, su IP y su estado."""
        with self._lock:
            self.reload()
            entry = self._ip_bucket(ip)
            now = int(time.time())
            requested_at = int(entry.get("requested_at", 0))
            code = str(entry.get("request_code") or "")
            fresh = bool(code) and now - requested_at < REQUEST_TTL
            until = int(entry.get("unlocked_until", 0))
            return {
                "token": "",
                "label": "",
                "codigo": code if fresh else "",
                "codigo_caduca": (requested_at + REQUEST_TTL) if fresh else 0,
                "ip": ip,
                "modo": MODE_UNLOCKED if until > now else MODE_STRICT,
                "visto": int(entry.get("last_seen", 0)),
                "desbloqueado_hasta": until,
            }

    def find_ip_by_request_code(self, code: str) -> str:
        """Que telefono (que IP) esta esperando este codigo."""
        code = str(code or "").strip()
        if not code:
            return ""
        now = int(time.time())
        with self._lock:
            self.reload()
            for ip, entry in self._ips.items():
                if str(entry.get("request_code") or "") != code:
                    continue
                if now - int(entry.get("requested_at", 0)) >= REQUEST_TTL:
                    continue
                return ip
        return ""

    def _clear_request_ip(self, ip: str) -> None:
        with self._lock:
            self.reload()
            entry = self._ips.get(str(ip or ""))
            if entry is None or not entry.get("request_code"):
                return
            entry["request_code"] = ""
            entry["requested_at"] = 0
            self._schedule_write()

    def pending_requests(self) -> list[dict[str, Any]]:
        """Dispositivos esperando autorizacion, del mas reciente al mas viejo."""
        now = int(time.time())
        rows: list[dict[str, Any]] = []
        with self._lock:
            self.reload()
            for token, device in self._devices.items():
                code = str(device.get("request_code") or "")
                requested_at = int(device.get("requested_at", 0))
                if not code or now - requested_at >= REQUEST_TTL:
                    continue
                if int(device.get("unlocked_until", 0)) > now:
                    continue
                rows.append(
                    {
                        "token": token,
                        "label": str(device.get("label") or ""),
                        "codigo": code,
                        "solicitado": requested_at,
                        "ip": str(device.get("last_ip") or ""),
                    }
                )
            for ip, entry in self._ips.items():
                code = str(entry.get("request_code") or "")
                requested_at = int(entry.get("requested_at", 0))
                if not code or now - requested_at >= REQUEST_TTL:
                    continue
                if int(entry.get("unlocked_until", 0)) > now:
                    continue
                rows.append(
                    {
                        "token": "",
                        "label": "",
                        "codigo": code,
                        "solicitado": requested_at,
                        "ip": ip,
                    }
                )
        return sorted(rows, key=lambda row: row["solicitado"], reverse=True)

    def approve(self, code: str, hours: int, license_code: str = "") -> dict[str, Any]:
        """Autoriza a quien ensena ese codigo y se lo deja sin codigo.

        Puede ser un equipo con token o un telefono con el perfil unico, que se
        identifica por su IP. En los dos casos la solicitud desaparece.
        """
        token = self.find_by_request_code(code)
        if token is not None:
            device = self.unlock(token, license_code, hours)
            self._clear_request(token)
            return dict(device, token=token)
        ip = self.find_ip_by_request_code(code)
        if not ip:
            raise KeyError(code)
        entry = self.unlock_ip(ip, license_code, hours)
        self._clear_request_ip(ip)
        return dict(entry, token="", ip=ip)

    def deny(self, code: str) -> str | None:
        """Rechaza la solicitud. Devuelve el token afectado, o "" si fue por IP."""
        token = self.find_by_request_code(code)
        if token is not None:
            self._clear_request(token)
            return token
        ip = self.find_ip_by_request_code(code)
        if ip:
            self._clear_request_ip(ip)
            return ""
        return None

    def find_by_request_code(self, code: str) -> str | None:
        code = str(code or "").strip()
        if not code:
            return None
        with self._lock:
            self.reload()
            for token, device in self._devices.items():
                if str(device.get("request_code") or "") == code:
                    return token
        return None

    def token_by_ip(self, ip: str) -> str | None:
        """Ultimo dispositivo visto desde esa IP, para el portal cautivo."""
        ip = str(ip or "")
        if not ip:
            return None
        with self._lock:
            self.reload()
            best: tuple[int, str] | None = None
            for token, device in self._devices.items():
                if str(device.get("last_ip") or "") != ip:
                    continue
                seen = int(device.get("last_seen", 0))
                if best is None or seen > best[0]:
                    best = (seen, token)
        return best[1] if best else None

    def _clear_request(self, token: str) -> None:
        with self._lock:
            device = self._devices.get(token)
            if device is None:
                return
            device["request_code"] = ""
            device["requested_at"] = 0
            self._schedule_write()

    def note_ip(self, token: str | None, ip: str) -> None:
        if not token or not ip:
            return
        with self._lock:
            device = self._devices.get(token)
            if device is None:
                return
            if str(device.get("last_ip") or "") == ip:
                return
            device["last_ip"] = ip
            self._dirty_touch.add(token)

    def list(self) -> list[dict[str, Any]]:
        self.reload()
        with self._lock:
            return [
                dict(device, token=token) for token, device in sorted(self._devices.items())
            ]

    def touch(self, token: str | None) -> None:
        """Marca actividad. Solo escribe en disco de vez en cuando."""
        if not token:
            return
        with self._lock:
            device = self._devices.get(token)
            if device is None:
                return
            device["last_seen"] = int(time.time())
            self._dirty_touch.add(token)
            now = time.monotonic()
            if now - self._last_touch_write >= TOUCH_INTERVAL:
                self._last_touch_write = now
                self._dirty_touch.clear()
                self._schedule_write()

    def flush(self) -> None:
        with self._lock:
            if self._dirty_touch:
                self._dirty_touch.clear()
                self._schedule_write()
