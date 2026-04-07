from __future__ import annotations

import json
import time
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
STATE_DIR = APP_DIR / "state"
RESTORE_IGNORE_FILE = STATE_DIR / "restore_ignore.json"
DEFAULT_RESTORE_IGNORE_TTL_SECONDS = 90


def _load_map() -> dict[str, float]:
    if not RESTORE_IGNORE_FILE.exists():
        return {}
    try:
        with RESTORE_IGNORE_FILE.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            return {}
        result: dict[str, float] = {}
        for key, value in payload.items():
            try:
                result[str(Path(key).resolve())] = float(value)
            except Exception:
                continue
        return result
    except Exception:
        return {}


def _save_map(data: dict[str, float]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with RESTORE_IGNORE_FILE.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def purge_expired_entries(data: dict[str, float] | None = None) -> dict[str, float]:
    current = dict(data or _load_map())
    now = time.time()
    return {path: expiry for path, expiry in current.items() if expiry > now}


def remember_restored_path(path: str | Path, ttl_seconds: int = DEFAULT_RESTORE_IGNORE_TTL_SECONDS) -> None:
    current = purge_expired_entries()
    current[str(Path(path).expanduser().resolve())] = time.time() + max(5, int(ttl_seconds))
    _save_map(current)


def should_ignore_restored_path(path: str | Path) -> bool:
    current = purge_expired_entries()
    normalized = str(Path(path).expanduser().resolve())
    expiry = current.get(normalized)
    if not expiry:
        return False
    _save_map(current)
    return expiry > time.time()
