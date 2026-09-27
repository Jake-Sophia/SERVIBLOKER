from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from typing import Any

BLOCKED = "blocked"
ERROR = "error"
ALLOWED = "allowed"


class QueryLog:
    """Registro en disco de las consultas bloqueadas.

    Sirve para descubrir dominios que se escapan de las listas: se consulta con
    `blockservi log` y se añaden a policy.json.
    """

    def __init__(self, path: str, max_bytes: int = 8 * 1024 * 1024, keep: int = 500) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self._recent: deque[dict[str, Any]] = deque(maxlen=keep)
        self._lock = threading.Lock()

    def _rotate_if_needed(self) -> None:
        try:
            if os.path.getsize(self.path) < self.max_bytes:
                return
        except OSError:
            return
        os.replace(self.path, f"{self.path}.1")

    def record(self, kind: str, name: str, qtype: str, reason: str, device: str, mode: str) -> None:
        entry = {
            "at": int(time.time()),
            "kind": kind,
            "device": device,
            "mode": mode,
            "name": name,
            "qtype": qtype,
            "reason": reason,
        }
        with self._lock:
            self._recent.append(entry)
            line = json.dumps(entry, ensure_ascii=False)
            try:
                os.makedirs(os.path.dirname(self.path) or ".", mode=0o700, exist_ok=True)
                self._rotate_if_needed()
                with open(self.path, "a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
            except OSError:
                pass

    def recent(self, limit: int = 50, only_blocked: bool = True) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._recent)
        if only_blocked:
            items = [item for item in items if item["kind"] == BLOCKED]
        return items[-limit:][::-1]

    def tail_file(self, limit: int = 50) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            return []
        return entries[-limit:][::-1]
