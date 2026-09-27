from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Iterable

ALLOW = "allow"
DENY = "deny"

MODE_STRICT = "strict"
MODE_UNLOCKED = "unlocked"


class PolicyError(Exception):
    pass


@dataclass(frozen=True)
class Rule:
    kind: str
    value: str

    def matches(self, name: str) -> bool:
        if self.kind == "exact":
            return name == self.value
        if self.kind == "suffix":
            return name == self.value or name.endswith("." + self.value)
        if self.kind == "regex":
            return self.value.search(name) is not None
        raise PolicyError(f"Tipo de regla desconocido: {self.kind}")


@dataclass(frozen=True)
class Decision:
    allow: bool
    mode: str
    reason: str
    rule: Rule | None = None
    permanent: bool = False


def normalize(name: str) -> str:
    return name.strip().lower().rstrip(".")


def _build(entries: Iterable[str]) -> list[Rule]:
    rules: list[Rule] = []
    for raw in entries:
        entry = raw.strip()
        if not entry or entry.startswith("#"):
            continue
        if entry.startswith("re:"):
            rules.append(Rule("regex", re.compile(entry[3:].strip())))
            continue
        if entry.startswith("="):
            rules.append(Rule("exact", normalize(entry[1:])))
            continue
        rules.append(Rule("suffix", normalize(entry)))
    return rules


class Policy:
    """Lista blanca estricta por defecto, con una lista de bloqueo permanente."""

    def __init__(self, spec: dict) -> None:
        self.spec = spec
        self.deny_always: list[Rule] = _build(spec.get("deny_always", []))
        self.deny_strict: list[Rule] = _build(spec.get("deny_strict", []))
        self.allow_strict: list[Rule] = _build(spec.get("allow_strict", []))
        self.allow_strict_optional: list[Rule] = _build(spec.get("allow_strict_optional", []))
        self.blocked_qtypes: set[str] = {
            item.strip().upper() for item in spec.get("blocked_qtypes", []) if item.strip()
        }
        self.strict_push: bool = bool(spec.get("strict_push", True))

    def ensure_allowed(self, names: Iterable[str]) -> None:
        """Anade dominios que siempre deben resolverse, como el portal y el propio DNS."""
        for name in names:
            entry = normalize(name)
            if not entry:
                continue
            if not any(rule.matches(entry) for rule in self.allow_strict):
                self.allow_strict.append(Rule("suffix", entry))

    @classmethod
    def load(cls, path: str) -> "Policy":
        with open(path, "r", encoding="utf-8") as handle:
            spec = json.load(handle)
        if not isinstance(spec, dict):
            raise PolicyError(f"{path}: se esperaba un objeto JSON")
        return cls(spec)

    def _match(self, rules: list[Rule], name: str) -> Rule | None:
        for rule in rules:
            if rule.matches(name):
                return rule
        return None

    def check_qtype(self, qtype: str) -> Decision | None:
        if qtype.upper() in self.blocked_qtypes:
            return Decision(
                False, MODE_STRICT, f"tipo de consulta bloqueado: {qtype.upper()}", permanent=True
            )
        return None

    def decide(self, raw_name: str, mode: str) -> Decision:
        name = normalize(raw_name)
        if not name:
            return Decision(False, mode, "nombre vacio")

        rule = self._match(self.deny_always, name)
        if rule is not None:
            return Decision(False, mode, f"bloqueo permanente: {rule.value}", rule, permanent=True)

        if mode == MODE_UNLOCKED:
            return Decision(True, mode, "acceso habilitado por codigo")

        rule = self._match(self.deny_strict, name)
        if rule is not None:
            return Decision(False, mode, f"bloqueo sin codigo: {rule.value}", rule)

        rule = self._match(self.allow_strict, name)
        if rule is not None:
            return Decision(True, mode, f"permitido siempre: {rule.value}", rule)

        if self.strict_push:
            rule = self._match(self.allow_strict_optional, name)
            if rule is not None:
                return Decision(True, mode, f"permitido en modo estricto: {rule.value}", rule)

        return Decision(False, mode, "no esta en la lista blanca")
