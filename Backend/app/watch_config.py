from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

APP_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = APP_DIR.parents[1]
CONFIG_DIR = APP_DIR / "config"
WATCH_CONFIG_FILE = CONFIG_DIR / "watch_targets.json"
DEFAULT_WINDOWS_STAGING_DIR = Path(r"D:\\Download")
DEFAULT_FALLBACK_STAGING_DIR = PROJECT_ROOT / "staging" / "Download"
DEFAULT_LINUX_CAPTURE_DIR = PROJECT_ROOT / "capture" / "DownloadInbox"


def is_linux_host() -> bool:
    return os.name == "posix" and "linux" in os.sys.platform


def is_windows_host() -> bool:
    return os.name == "nt"


def _normalize_dir(value: str | os.PathLike[str] | None) -> str | None:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    return str(Path(raw).expanduser().resolve())


def _dedupe_dirs(values: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(value)
    return unique


def get_quarantine_dir(config: dict[str, Any] | None = None) -> Path:
    raw_value = None
    if config:
        raw_value = config.get("quarantine_dir")
    if not raw_value:
        raw_value = os.environ.get("SANDBOX_STAGING_DIR")
    if raw_value:
        return Path(str(raw_value)).expanduser().resolve()
    if is_windows_host():
        return DEFAULT_WINDOWS_STAGING_DIR
    return DEFAULT_FALLBACK_STAGING_DIR.resolve()


def get_release_dir(config: dict[str, Any] | None = None) -> Path:
    raw_value = None
    if config:
        raw_value = config.get("release_dir")
    if raw_value:
        return Path(str(raw_value)).expanduser().resolve()
    return (Path.home() / "Downloads").resolve()


def get_capture_inbox_dir(config: dict[str, Any] | None = None) -> Path:
    raw_value = None
    if config:
        raw_value = config.get("capture_inbox_dir")
    if raw_value:
        return Path(str(raw_value)).expanduser().resolve()
    if is_linux_host():
        return DEFAULT_LINUX_CAPTURE_DIR.resolve()
    return (Path.home() / "Downloads").resolve()


def default_watch_directories() -> list[str]:
    defaults = [str(get_capture_inbox_dir())]
    return _dedupe_dirs(defaults)


def default_external_mount_roots() -> list[str]:
    candidates: list[str] = []
    user_name = os.environ.get("USER") or Path.home().name
    if is_linux_host():
        candidates.extend(
            [
                f"/run/media/{user_name}",
                f"/media/{user_name}",
                "/mnt",
            ]
        )
    normalized = [_normalize_dir(path) for path in candidates]
    return _dedupe_dirs([path for path in normalized if path])


def get_default_watch_config() -> dict[str, Any]:
    quarantine_dir = str(get_quarantine_dir())
    release_dir = str(get_release_dir())
    capture_inbox_dir = str(get_capture_inbox_dir())
    return {
        "selected_directories": default_watch_directories(),
        "watch_external_drives": True,
        "external_mount_roots": default_external_mount_roots(),
        "quarantine_dir": quarantine_dir,
        "release_dir": release_dir,
        "capture_inbox_dir": capture_inbox_dir,
    }


def sanitize_watch_config(payload: dict[str, Any] | None) -> dict[str, Any]:
    source = dict(payload or {})
    config = get_default_watch_config()
    config.update(source)

    quarantine_dir = get_quarantine_dir(config)
    release_dir = get_release_dir(config)
    capture_inbox_dir = get_capture_inbox_dir(config)

    raw_directories = source.get("selected_directories", config.get("selected_directories", []))
    if not isinstance(raw_directories, list):
        raw_directories = config["selected_directories"]

    selected_directories: list[str] = []
    quarantine_str = str(quarantine_dir)
    for raw_dir in raw_directories:
        normalized = _normalize_dir(raw_dir)
        if not normalized:
            continue
        candidate = Path(normalized)
        if candidate == quarantine_dir:
            continue
        if quarantine_str.startswith(f"{normalized}{os.sep}"):
            continue
        selected_directories.append(normalized)

    config["selected_directories"] = _dedupe_dirs(selected_directories) or default_watch_directories()
    config["watch_external_drives"] = bool(config.get("watch_external_drives", True))

    raw_roots = source.get("external_mount_roots", config.get("external_mount_roots", []))
    if not isinstance(raw_roots, list):
        raw_roots = config["external_mount_roots"]
    external_mount_roots = [_normalize_dir(item) for item in raw_roots]
    config["external_mount_roots"] = _dedupe_dirs([item for item in external_mount_roots if item])
    config["quarantine_dir"] = quarantine_str
    config["release_dir"] = str(release_dir)
    config["capture_inbox_dir"] = str(capture_inbox_dir)
    return config


def load_watch_config() -> dict[str, Any]:
    config = get_default_watch_config()
    if WATCH_CONFIG_FILE.exists():
        try:
            with WATCH_CONFIG_FILE.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
            if isinstance(payload, dict):
                config.update(payload)
        except Exception:
            pass
    return sanitize_watch_config(config)


def save_watch_config(payload: dict[str, Any]) -> dict[str, Any]:
    config = sanitize_watch_config(payload)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with WATCH_CONFIG_FILE.open("w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)
    return config


def _read_proc_mounts() -> list[str]:
    mounts: list[str] = []
    proc_mounts = Path("/proc/mounts")
    if not proc_mounts.exists():
        return mounts

    try:
        with proc_mounts.open("r", encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) < 2:
                    continue
                mount_point = parts[1].replace("\\040", " ")
                normalized = _normalize_dir(mount_point)
                if normalized:
                    mounts.append(normalized)
    except Exception:
        return []

    return _dedupe_dirs(mounts)


def get_detected_external_directories(config: dict[str, Any] | None = None) -> list[str]:
    active_config = sanitize_watch_config(config or load_watch_config())
    if not active_config.get("watch_external_drives"):
        return []

    roots = [Path(root) for root in active_config.get("external_mount_roots", []) if root]
    if not roots:
        return []

    detected: list[str] = []
    for mount_point in _read_proc_mounts():
        candidate = Path(mount_point)
        for root in roots:
            if candidate == root or root in candidate.parents:
                if candidate.is_dir():
                    detected.append(str(candidate))
                break

    for root in roots:
        if not root.exists() or not root.is_dir():
            continue
        try:
            for entry in root.iterdir():
                if entry.is_dir():
                    detected.append(str(entry.resolve()))
        except Exception:
            continue

    quarantine_dir = str(get_quarantine_dir(active_config))
    filtered = []
    for item in _dedupe_dirs(detected):
        if item == quarantine_dir or quarantine_dir.startswith(f"{item}{os.sep}"):
            continue
        filtered.append(item)
    return filtered


def get_runtime_watch_directories(config: dict[str, Any] | None = None) -> list[str]:
    active_config = sanitize_watch_config(config or load_watch_config())
    all_dirs = list(active_config.get("selected_directories", []))
    all_dirs.extend(get_detected_external_directories(active_config))
    quarantine_dir = str(get_quarantine_dir(active_config))
    filtered = []
    for item in _dedupe_dirs(all_dirs):
        if item == quarantine_dir or quarantine_dir.startswith(f"{item}{os.sep}"):
            continue
        filtered.append(item)
    return filtered


def build_watch_config_response(config: dict[str, Any] | None = None) -> dict[str, Any]:
    active_config = sanitize_watch_config(config or load_watch_config())
    selected_directories = active_config.get("selected_directories", [])
    detected_external_directories = get_detected_external_directories(active_config)
    active_directories = get_runtime_watch_directories(active_config)

    missing_directories = [
        item
        for item in selected_directories
        if not Path(item).exists()
    ]

    return {
        "selected_directories": selected_directories,
        "watch_external_drives": bool(active_config.get("watch_external_drives")),
        "external_mount_roots": active_config.get("external_mount_roots", []),
        "detected_external_directories": detected_external_directories,
        "active_watch_directories": active_directories,
        "missing_directories": missing_directories,
        "quarantine_dir": str(get_quarantine_dir(active_config)),
        "release_dir": str(get_release_dir(active_config)),
        "capture_inbox_dir": str(get_capture_inbox_dir(active_config)),
    }
