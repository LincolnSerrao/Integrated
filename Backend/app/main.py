from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.sandbox_status import get_sandbox_provider_name, get_sandbox_status as read_sandbox_status
from app.scanner import SCAN_LOG_FILE, ml_stack_status, scan_file, write_scan_event
from app.monitor_state import remember_restored_path
from app.watch_config import (
    build_watch_config_response,
    get_capture_inbox_dir,
    get_quarantine_dir,
    get_release_dir,
    get_runtime_watch_directories,
    load_watch_config,
    save_watch_config,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MAX_FILE_SIZE_BYTES = 1024 * 1024 * 1024  # 1 GB
SCAN_RESULTS: dict[str, dict[str, Any]] = {}
APP_STARTED_AT = datetime.now(timezone.utc)
STAGING_DIR = get_quarantine_dir(load_watch_config())

app = FastAPI(title="Sandbox Upload API", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class WatchTargetsUpdate(BaseModel):
    directories: list[str]
    watch_external_drives: bool = True


class RestoreRequest(BaseModel):
    target_directory: str | None = None


def ensure_staging_dir() -> None:
    global STAGING_DIR
    STAGING_DIR = get_quarantine_dir(load_watch_config())
    STAGING_DIR.mkdir(parents=True, exist_ok=True)


def safe_unique_path(original_name: str) -> Path:
    file_name = Path(original_name).name or "upload.bin"
    target = STAGING_DIR / file_name
    if not target.exists():
        return target

    stem = Path(file_name).stem
    suffix = Path(file_name).suffix
    return STAGING_DIR / f"{stem}_{uuid4().hex[:8]}{suffix}"


def decision_to_result(decision: str) -> str:
    if decision == "BLOCKED":
        return "Malicious"
    if decision == "UNCERTAIN":
        return "Suspicious"
    return "Safe"


def parse_event_ts(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def process_staged_file(target_path: Path) -> dict[str, Any]:
    try:
        scan_result = scan_file(target_path)
    except FileNotFoundError:
        scan_result = {
            "decision": "UNCERTAIN",
            "engine": "handoff",
            "fused_risk": 0.5,
            "reasons": [],
            "scanner_warning": "File was handed off to the sandbox monitor before local scanning completed.",
        }
    except Exception as exc:
        scan_result = {
            "decision": "UNCERTAIN",
            "engine": "none",
            "fused_risk": 0.5,
            "reasons": [],
            "scanner_warning": str(exc),
        }

    overall_result = decision_to_result(scan_result.get("decision", "UNCERTAIN"))
    payload = {
        "status": "queued",
        "file_name": target_path.name,
        "staging_path": str(target_path),
        "size_bytes": target_path.stat().st_size if target_path.exists() else 0,
        "scan_result": scan_result,
        "overall_result": overall_result,
    }
    SCAN_RESULTS[target_path.name] = payload
    return payload


def read_scan_logs(limit: int) -> list[dict[str, Any]]:
    if not SCAN_LOG_FILE.exists():
        return []

    ordered_events: list[tuple[int, dict[str, Any]]] = []
    with SCAN_LOG_FILE.open("r", encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            line = line.strip()
            if not line:
                continue
            try:
                event = dict(json.loads(line))
            except Exception:
                continue
            event["overall_result"] = decision_to_result(str(event.get("decision", "UNCERTAIN")))
            ordered_events.append((index, event))

    ordered_events.sort(key=lambda item: (str(item[1].get("ts", "")), item[0]), reverse=True)
    return [event for _, event in ordered_events[:limit]]


def get_latest_log_event(current_session_only: bool = False) -> dict[str, Any] | None:
    items = read_scan_logs(limit=500)
    if current_session_only:
        items = [
            item
            for item in items
            if (parse_event_ts(item.get("ts")) or datetime.min.replace(tzinfo=timezone.utc)) >= APP_STARTED_AT
        ]
    if not items:
        return None
    return items[0]


def find_logged_event(file_name: str) -> dict[str, Any] | None:
    safe_name = Path(file_name).name
    if not safe_name or not SCAN_LOG_FILE.exists():
        return None

    latest_match: dict[str, Any] | None = None
    with SCAN_LOG_FILE.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = dict(json.loads(line))
            except Exception:
                continue
            if Path(str(event.get("file_name", ""))).name != safe_name:
                continue
            latest_match = event
    if latest_match:
        latest_match["overall_result"] = decision_to_result(str(latest_match.get("decision", "UNCERTAIN")))
    return latest_match


def payload_from_logged_event(event: dict[str, Any]) -> dict[str, Any]:
    file_path = Path(str(event.get("path") or ""))
    return {
        "status": event.get("post_action") or "logged",
        "file_name": event.get("file_name") or file_path.name,
        "staging_path": str(file_path),
        "size_bytes": file_path.stat().st_size if file_path.exists() and file_path.is_file() else 0,
        "scan_result": event,
        "overall_result": event.get("overall_result") or decision_to_result(str(event.get("decision", "UNCERTAIN"))),
    }


def resolve_scan_context(file_name: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    safe_name = Path(file_name).name
    return SCAN_RESULTS.get(safe_name), find_logged_event(safe_name)


def resolve_managed_file(file_name: str) -> Path:
    safe_name = Path(file_name).name
    if not safe_name:
        raise HTTPException(status_code=400, detail="Invalid file name")

    candidates: list[Path] = []
    candidates.append(STAGING_DIR / safe_name)

    record, logged_event = resolve_scan_context(safe_name)
    if record:
        staging_path = record.get("staging_path")
        if staging_path:
            candidates.append(Path(str(staging_path)))
        scan_result = record.get("scan_result") or {}
        scan_path = scan_result.get("path")
        if scan_path:
            candidates.append(Path(str(scan_path)))

    if logged_event and logged_event.get("post_action") in (None, "manual_review_required", "logged"):
        logged_path = logged_event.get("path")
        if logged_path:
            candidates.append(Path(str(logged_path)))

    seen: set[str] = set()
    for candidate in candidates:
        candidate_key = str(candidate).lower()
        if candidate_key in seen:
            continue
        seen.add(candidate_key)
        if candidate.exists() and candidate.is_file():
            return candidate

    raise HTTPException(status_code=404, detail="File not found in quarantine")


def choose_restore_target(
    file_name: str,
    logged_event: dict[str, Any] | None,
    target_directory: str | None = None,
) -> Path:
    configured_release_dir = get_release_dir(load_watch_config())
    original_path = None if not logged_event else logged_event.get("original_path")
    if target_directory:
        destination_dir = Path(str(target_directory)).expanduser().resolve()
        destination_dir.mkdir(parents=True, exist_ok=True)
        target = destination_dir / Path(file_name).name
    else:
        target = Path(str(original_path)).expanduser() if original_path else configured_release_dir / Path(file_name).name
    target = target.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        return target
    stem = target.stem
    suffix = target.suffix
    counter = 1
    while True:
        candidate = target.with_name(f"{stem}_{counter}{suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def log_post_action(scan_payload: dict[str, Any], post_action: str, message: str, **extra: Any) -> dict[str, Any]:
    payload = dict(scan_payload)
    payload["post_action"] = post_action
    payload["message"] = message
    payload["overall_result"] = decision_to_result(str(payload.get("decision", "UNCERTAIN")))
    payload.update(extra)
    return write_scan_event(payload)


def _path_is_same_or_nested(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return candidate == parent


def validate_release_directory(target_directory: str) -> Path:
    target = Path(str(target_directory)).expanduser().resolve()
    config = load_watch_config()
    quarantine_dir = get_quarantine_dir(config).resolve()
    if _path_is_same_or_nested(target, quarantine_dir):
        raise HTTPException(status_code=400, detail="Choose a destination outside the quarantine directory")

    for watch_dir in get_runtime_watch_directories(config):
        watch_path = Path(watch_dir).expanduser().resolve()
        if _path_is_same_or_nested(target, watch_path):
            raise HTTPException(status_code=400, detail="Choose a destination outside the active capture folders")

    target.mkdir(parents=True, exist_ok=True)
    return target


def _upsert_user_dir_entry(content: str, key: str, value: str) -> str:
    lines = content.splitlines()
    entry = f'{key}="{value}"'
    replaced = False
    for index, line in enumerate(lines):
        if line.strip().startswith(f"{key}="):
            lines[index] = entry
            replaced = True
            break
    if not replaced:
        lines.append(entry)
    return "\n".join(lines).rstrip() + "\n"


def configure_linux_download_capture(capture_dir: Path) -> Path:
    config_dir = Path.home() / ".config"
    config_dir.mkdir(parents=True, exist_ok=True)
    user_dirs_path = config_dir / "user-dirs.dirs"
    current = ""
    if user_dirs_path.exists():
        current = user_dirs_path.read_text(encoding="utf-8")
    if not current.strip():
        current = '# Managed by Cyber Shield Innovators\n'
    updated = _upsert_user_dir_entry(current, 'XDG_DOWNLOAD_DIR', str(capture_dir))
    user_dirs_path.write_text(updated, encoding="utf-8")
    return user_dirs_path


def ensure_always_on_capture() -> None:
    current = load_watch_config()
    capture_dir = get_capture_inbox_dir(current).resolve()
    release_dir = get_release_dir(current).resolve()
    capture_dir.mkdir(parents=True, exist_ok=True)
    release_dir.mkdir(parents=True, exist_ok=True)

    updated = {
        **current,
        "selected_directories": [str(capture_dir)],
        "capture_inbox_dir": str(capture_dir),
        "release_dir": str(release_dir),
        "watch_external_drives": True,
    }
    save_watch_config(updated)
    configure_linux_download_capture(capture_dir)


@app.on_event("startup")
def on_startup() -> None:
    ensure_always_on_capture()
    ensure_staging_dir()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/scan/ml-status")
def get_ml_status() -> dict[str, Any]:
    return ml_stack_status()


@app.get("/api/scan/sandbox-status")
def get_sandbox_status() -> dict[str, Any]:
    return read_sandbox_status()


@app.get("/api/scan/config")
def get_scan_config() -> dict[str, Any]:
    ensure_staging_dir()
    provider_name = get_sandbox_provider_name()
    watch_config = build_watch_config_response(load_watch_config())
    return {
        "mode": "multi-watch-quarantine",
        "staging_dir": str(STAGING_DIR),
        "provider_name": provider_name,
        "message": (
            "Automatic capture is always on while the software is running. "
            f"System downloads and mounted external drives are moved into {STAGING_DIR} for review."
        ),
        **watch_config,
    }


@app.get("/api/scan/watch-targets")
def get_watch_targets() -> dict[str, Any]:
    return build_watch_config_response(load_watch_config())


@app.put("/api/scan/watch-targets")
def update_watch_targets(payload: WatchTargetsUpdate) -> dict[str, Any]:
    current = load_watch_config()
    updated = save_watch_config(
        {
            **current,
            "selected_directories": payload.directories,
            "watch_external_drives": payload.watch_external_drives,
        }
    )
    ensure_staging_dir()
    return build_watch_config_response(updated)


def pick_directory_with_dialog(title: str) -> dict[str, Any]:
    if os.name == "nt":
        raise HTTPException(status_code=400, detail="Directory picker endpoint is only configured for KDE/Linux right now")
    if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        raise HTTPException(status_code=400, detail="No desktop session detected for directory picker")

    command = ["kdialog", "--getexistingdirectory", str(Path.home()), title]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=120)
    except FileNotFoundError:
        raise HTTPException(status_code=400, detail="kdialog is not installed on this machine")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Directory picker timed out")

    if completed.returncode != 0:
        raise HTTPException(status_code=400, detail="Directory picker was cancelled")

    selected = completed.stdout.strip()
    if not selected:
        raise HTTPException(status_code=400, detail="No directory selected")

    return {"directory": str(Path(selected).expanduser().resolve())}


@app.post("/api/scan/pick-directory")
def pick_directory() -> dict[str, Any]:
    return pick_directory_with_dialog("Choose a folder to monitor")


@app.post("/api/scan/pick-release-directory")
def pick_release_directory() -> dict[str, Any]:
    return pick_directory_with_dialog("Choose where to save the safe file")


@app.post("/api/scan/strict-capture/apply")
def apply_strict_capture() -> dict[str, Any]:
    if os.name == "nt":
        raise HTTPException(status_code=400, detail="Strict pre-download capture is only configured for Linux/KDE in this build")

    current = load_watch_config()
    capture_dir = get_capture_inbox_dir(current).resolve()
    release_dir = get_release_dir(current).resolve()
    capture_dir.mkdir(parents=True, exist_ok=True)
    release_dir.mkdir(parents=True, exist_ok=True)
    user_dirs_path = configure_linux_download_capture(capture_dir)

    updated = save_watch_config(
        {
            **current,
            "selected_directories": [str(capture_dir)],
            "capture_inbox_dir": str(capture_dir),
            "release_dir": str(release_dir),
        }
    )
    ensure_staging_dir()
    return {
        "status": "strict_capture_enabled",
        "message": (
            "System downloads now point to the capture inbox first. Restart browsers or file-transfer apps so they use the new download directory."
        ),
        "user_dirs_path": str(user_dirs_path),
        **build_watch_config_response(updated),
    }


@app.post("/api/scan/upload")
async def upload_to_sandbox(file: UploadFile = File(...)) -> dict[str, Any]:
    ensure_staging_dir()

    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    target_path = safe_unique_path(file.filename)
    total = 0

    try:
        with target_path.open("wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_FILE_SIZE_BYTES:
                    raise HTTPException(status_code=413, detail="File too large")
                out.write(chunk)
    except HTTPException:
        if target_path.exists():
            target_path.unlink(missing_ok=True)
        raise
    except Exception as exc:
        if target_path.exists():
            target_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Upload failed: {exc}")
    finally:
        await file.close()

    payload = process_staged_file(target_path)
    payload["size_bytes"] = total
    SCAN_RESULTS[target_path.name] = payload
    return payload


@app.get("/api/scan/results/{file_name}")
def get_scan_result(file_name: str) -> dict[str, Any]:
    safe_name = Path(file_name).name
    record, logged_event = resolve_scan_context(safe_name)
    if record:
        return record
    if logged_event:
        return payload_from_logged_event(logged_event)
    raise HTTPException(status_code=404, detail="No scan result found for this file")


@app.get("/api/scan/logs")
def get_scan_logs(
    limit: int = Query(default=50, ge=1, le=500),
    current_session_only: bool = Query(default=False),
) -> dict[str, Any]:
    items = read_scan_logs(500 if current_session_only else limit)
    if current_session_only:
        items = [
            item
            for item in items
            if (parse_event_ts(item.get("ts")) or datetime.min.replace(tzinfo=timezone.utc)) >= APP_STARTED_AT
        ][:limit]
    return {"count": len(items), "items": items}


@app.get("/api/scan/latest")
def get_latest_scan_result() -> dict[str, Any]:
    latest = get_latest_log_event(current_session_only=True)
    if not latest:
        raise HTTPException(status_code=404, detail="No scan results available in this session")
    return latest


@app.get("/api/scan/files/{file_name}")
def download_file(file_name: str) -> FileResponse:
    file_path = resolve_managed_file(file_name)
    return FileResponse(path=file_path, filename=file_path.name, media_type="application/octet-stream")


@app.post("/api/scan/files/{file_name}/restore")
def restore_file(file_name: str, payload: RestoreRequest | None = None) -> dict[str, Any]:
    file_path = resolve_managed_file(file_name)
    _, logged_event = resolve_scan_context(file_name)
    target_directory = payload.target_directory if payload else None
    if target_directory:
        validate_release_directory(target_directory)
    target_path = choose_restore_target(file_name, logged_event, target_directory=target_directory)

    try:
        shutil.move(str(file_path), str(target_path))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Restore failed: {exc}")

    SCAN_RESULTS.pop(file_path.name, None)
    remember_restored_path(target_path)
    if logged_event:
        log_post_action(
            logged_event,
            "restored_to_source",
            f"File restored to {target_path}",
            path=str(target_path),
            restored_path=str(target_path),
        )

    return {"status": "restored", "file_name": target_path.name, "restored_path": str(target_path)}


@app.delete("/api/scan/files/{file_name}")
def delete_file(file_name: str) -> dict[str, str]:
    file_path = resolve_managed_file(file_name)
    _, logged_event = resolve_scan_context(file_name)

    try:
        file_path.unlink()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Delete failed: {exc}")

    SCAN_RESULTS.pop(file_path.name, None)
    if logged_event:
        log_post_action(
            logged_event,
            "deleted_from_quarantine",
            f"File deleted from quarantine: {file_path.name}",
            path=str(file_path),
        )
    return {"status": "deleted", "file_name": file_path.name}
