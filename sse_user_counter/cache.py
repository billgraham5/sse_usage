from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CachedSwgCorrelation:
    user_name: str
    first_seen: str = ""
    last_seen: str = ""


class CorrelationCache:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path.home() / ".sse_user_counter" / "swg_correlation_cache.json"
        self._payload: dict[str, Any] | None = None

    def get_swg_correlation(
        self,
        *,
        product: str,
        scope_key: str,
        computer_name: str,
    ) -> CachedSwgCorrelation | None:
        entries = self._load()["swg_correlations"]
        entry = entries.get(self._entry_key(product, scope_key, computer_name))
        if not isinstance(entry, dict):
            return None
        user_name = str(entry.get("user_name", "")).strip()
        if not user_name:
            return None
        return CachedSwgCorrelation(
            user_name=user_name,
            first_seen=str(entry.get("first_seen", "")).strip(),
            last_seen=str(entry.get("last_seen", "")).strip(),
        )

    def set_swg_correlation(
        self,
        *,
        product: str,
        scope_key: str,
        computer_name: str,
        user_name: str,
        first_seen: str = "",
        last_seen: str = "",
    ) -> None:
        user_name = user_name.strip()
        if not user_name:
            return

        payload = self._load()
        payload["swg_correlations"][self._entry_key(product, scope_key, computer_name)] = {
            "computer_name": computer_name.strip(),
            "user_name": user_name,
            "first_seen": first_seen.strip(),
            "last_seen": last_seen.strip(),
        }
        self._write()

    def _load(self) -> dict[str, Any]:
        if self._payload is not None:
            return self._payload

        try:
            raw = self.path.read_text(encoding="utf-8")
            payload = json.loads(raw)
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            payload = {}

        if not isinstance(payload, dict):
            payload = {}
        correlations = payload.get("swg_correlations")
        if not isinstance(correlations, dict):
            correlations = {}

        self._payload = {"version": 1, "swg_correlations": correlations}
        return self._payload

    def _write(self) -> None:
        if self._payload is None:
            return

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = self.path.with_suffix(".tmp")
            temp_path.write_text(json.dumps(self._payload, indent=2, sort_keys=True), encoding="utf-8")
            temp_path.replace(self.path)
        except OSError:
            return

    @staticmethod
    def _entry_key(product: str, scope_key: str, computer_name: str) -> str:
        return "|".join((product.strip(), scope_key.strip(), computer_name.strip().casefold()))
