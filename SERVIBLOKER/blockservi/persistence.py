"""Serialización entre hilos/procesos para los JSON heredados (Linux/macOS)."""
from __future__ import annotations

import contextlib
import functools
import fcntl
import json
import os
import tempfile
import threading

_locks: dict[str, tuple[threading.RLock, threading.local]] = {}
_guard = threading.Lock()


@contextlib.contextmanager
def file_lock(path: str):
    path = os.path.abspath(path)
    with _guard:
        lock, local = _locks.setdefault(path, (threading.RLock(), threading.local()))
    with lock:
        if getattr(local, "depth", 0):
            local.depth += 1
            try:
                yield
            finally:
                local.depth -= 1
            return
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            local.depth = 1
            yield
        finally:
            local.depth = 0
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def serialized(method):
    @functools.wraps(method)
    def call(self, *args, **kwargs):
        with file_lock(self.path + ".lock"), self._lock:
            self.reload()
            return method(self, *args, **kwargs)
    return call


def write_json(path: str, value) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".state-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        dirfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
