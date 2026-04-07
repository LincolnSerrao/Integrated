from __future__ import annotations

import logging
import mimetypes
import os
import shutil
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from queue import Empty, Queue
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_ROOT = PROJECT_ROOT / "Backend"
LOG_DIR = PROJECT_ROOT / "sandbox" / "logs"
LOG_FILE = LOG_DIR / "sandbox.log"
POLL_INTERVAL_SECONDS = 2
STABLE_CHECK_INTERVAL_SECONDS = 1.0
STABLE_CHECK_ROUNDS = 3
STABLE_WAIT_TIMEOUT_SECONDS = 60
LOCK_RETRY_DELAY_SECONDS = 1.0
MAX_LOCK_RETRIES = 10
PROCESS_COOLDOWN_SECONDS = 30
TEMP_DOWNLOAD_EXTENSIONS = (".crdownload", ".part", ".tmp", ".download")
IGNORED_FILE_NAMES = {"desktop.ini", "thumbs.db", ".ds_store"}
SKIPPED_DIR_NAMES = {".git", "node_modules", "__pycache__", ".venv", ".venv-ml"}

EXECUTABLE_EXTENSIONS = {".exe"}
COMMON_IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".svg",
    ".ico", ".heic", ".heif", ".avif", ".jfif", ".pjpeg", ".pjp", ".apng", ".jxl",
}

try:
    import imghdr
except Exception:  # pragma: no cover - stdlib availability differs by runtime
    imghdr = None

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.monitor_state import should_ignore_restored_path
from app.sandbox_status import get_sandbox_status
from app.linux_native_sandbox import analyze_file_in_native_sandbox
from app.scanner import current_model_identity, write_scan_event
from app.watch_config import (
    get_detected_external_directories,
    get_quarantine_dir,
    get_runtime_watch_directories,
    load_watch_config,
)


def is_temporary_download_path(path: str) -> bool:
    lower = path.lower()
    name = os.path.basename(lower)
    if name in IGNORED_FILE_NAMES:
        return True
    if name.startswith("unconfirmed") or name.startswith("~$"):
        return True
    return lower.endswith(TEMP_DOWNLOAD_EXTENSIONS)


def _looks_like_image(path: str) -> bool:
    mime_type, _ = mimetypes.guess_type(path)
    if mime_type and mime_type.startswith('image/'):
        return True
    if imghdr is None:
        return False
    try:
        return imghdr.what(path) is not None
    except OSError:
        return False


def should_capture_file(path: str) -> bool:
    suffix = Path(path).suffix.lower()
    if suffix in EXECUTABLE_EXTENSIONS:
        return True
    if suffix in COMMON_IMAGE_EXTENSIONS:
        return True
    return _looks_like_image(path)



def _sandbox_managed_scan_result(scan_result: dict[str, Any], managed_path: str, session: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = {**current_model_identity(), **dict(scan_result)}
    payload['path'] = str(managed_path)
    payload['file_name'] = Path(str(managed_path)).name
    payload['analysis_origin'] = 'project-sandbox'
    if session:
        payload['sandbox_session_id'] = session.get('session_id')
        payload['sandbox_sample_copy'] = session.get('sample_copy')
        payload['sandbox_session_root'] = session.get('session_root')
        payload['sandbox_mode'] = session.get('mode') or 'analysis'
        payload['analysis_runtime'] = session.get('analysis_runtime')
        payload['analysis_engine'] = session.get('analysis_engine')
    return payload


class SandboxDownloadMonitor:
    def __init__(self) -> None:
        self.running = False
        self.shutdown_requested = False
        self.file_queue: Queue[str] = Queue()
        self.worker_thread: threading.Thread | None = None
        self.poll_thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self.active_files: set[str] = set()
        self.recently_processed: dict[str, float] = {}
        self.known_file_state: dict[str, tuple[int, float]] = {}
        self.watch_directories: list[str] = []
        self.detected_external_directories: list[str] = []
        self.selected_directories: list[str] = []
        self.quarantine_dir = str(get_quarantine_dir(load_watch_config()))
        self._configure_logging()
        self._refresh_watch_configuration()

    def _configure_logging(self) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(
            filename=LOG_FILE,
            level=logging.INFO,
            format="%(asctime)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def _refresh_watch_configuration(self) -> None:
        config = load_watch_config()
        self.quarantine_dir = str(get_quarantine_dir(config))
        Path(self.quarantine_dir).mkdir(parents=True, exist_ok=True)
        self.selected_directories = list(config.get("selected_directories", []))
        self.detected_external_directories = get_detected_external_directories(config)
        self.watch_directories = get_runtime_watch_directories(config)

    def _log_action(self, action: str, path: str) -> None:
        name = os.path.basename(path.rstrip(os.sep)) or path
        message = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {action} {name}"
        logging.info(message)
        print(message)

    def _prune_cooldowns(self) -> None:
        now = time.time()
        expired = [path for path, expiry in self.recently_processed.items() if expiry <= now]
        for path in expired:
            self.recently_processed.pop(path, None)

    def _is_in_cooldown(self, path: str) -> bool:
        expiry = self.recently_processed.get(path)
        if expiry is None:
            return False
        if expiry <= time.time():
            self.recently_processed.pop(path, None)
            return False
        return True

    def _mark_cooldown(self, path: str) -> None:
        self.recently_processed[path] = time.time() + PROCESS_COOLDOWN_SECONDS

    def _is_within_quarantine(self, path: str) -> bool:
        normalized = str(Path(path).resolve())
        quarantine = self.quarantine_dir
        return normalized == quarantine or normalized.startswith(f"{quarantine}{os.sep}")

    def _should_skip_directory(self, path: str) -> bool:
        candidate = Path(path)
        if candidate.name in SKIPPED_DIR_NAMES:
            return True
        return self._is_within_quarantine(str(candidate))

    def _iter_watch_files(self):
        seen_roots: set[str] = set()
        for watch_dir in self.watch_directories:
            try:
                root = str(Path(watch_dir).resolve())
            except Exception:
                continue
            if root in seen_roots or not os.path.isdir(root):
                continue
            seen_roots.add(root)
            for current_root, dirs, files in os.walk(root):
                dirs[:] = [name for name in dirs if not self._should_skip_directory(os.path.join(current_root, name))]
                for name in files:
                    candidate = os.path.join(current_root, name)
                    if self._is_within_quarantine(candidate) or is_temporary_download_path(candidate):
                        continue
                    if not should_capture_file(candidate):
                        continue
                    yield candidate

    def _wait_for_stable_file(self, path: str) -> bool:
        same_count = 0
        previous_size = -1
        previous_mtime = -1.0
        start_time = time.time()

        while self.running and not self.shutdown_requested:
            if not os.path.exists(path):
                return False
            try:
                current_size = os.path.getsize(path)
                current_mtime = os.path.getmtime(path)
            except OSError:
                time.sleep(LOCK_RETRY_DELAY_SECONDS)
                continue

            if current_size > 0 and current_size == previous_size and current_mtime == previous_mtime:
                same_count += 1
                if same_count >= STABLE_CHECK_ROUNDS:
                    return True
            else:
                same_count = 0
                previous_size = current_size
                previous_mtime = current_mtime

            if time.time() - start_time > STABLE_WAIT_TIMEOUT_SECONDS:
                self._log_action("FILE_STABILITY_TIMEOUT", path)
                return False

            time.sleep(STABLE_CHECK_INTERVAL_SECONDS)

        return False

    def _move_with_retries(self, src: str, dst: str) -> bool:
        attempt = 0
        while attempt < MAX_LOCK_RETRIES:
            try:
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.move(src, dst)
                return True
            except (PermissionError, OSError):
                attempt += 1
                time.sleep(LOCK_RETRY_DELAY_SECONDS)
        return False

    def _get_unique_destination(self, directory: str, file_name: str) -> str:
        base, ext = os.path.splitext(file_name)
        candidate = os.path.join(directory, file_name)
        index = 1
        while os.path.exists(candidate):
            candidate = os.path.join(directory, f"{base}_{index}{ext}")
            index += 1
        return candidate

    def _snapshot_known_files(self) -> None:
        self._refresh_watch_configuration()
        self.known_file_state = {}
        for file_path in self._iter_watch_files():
            try:
                stat = os.stat(file_path)
            except OSError:
                continue
            self.known_file_state[file_path] = (stat.st_size, stat.st_mtime)

    def _poll_watch_dirs(self) -> None:
        self._refresh_watch_configuration()
        current_state: dict[str, tuple[int, float]] = {}

        for file_path in self._iter_watch_files():
            try:
                stat = os.stat(file_path)
            except OSError:
                continue

            state = (stat.st_size, stat.st_mtime)
            current_state[file_path] = state

            if should_ignore_restored_path(file_path):
                continue

            previous_state = self.known_file_state.get(file_path)
            if previous_state is None or previous_state != state:
                with self.lock:
                    if file_path not in self.active_files and not self._is_in_cooldown(file_path):
                        self.file_queue.put(file_path)

        self.known_file_state = current_state
        self._prune_cooldowns()

    def _poll_loop(self) -> None:
        while not self.shutdown_requested:
            if self.running:
                self._poll_watch_dirs()
            time.sleep(POLL_INTERVAL_SECONDS)

    def _source_label_for(self, path: str) -> str:
        resolved = str(Path(path).resolve())
        for external_dir in self.detected_external_directories:
            if resolved == external_dir or resolved.startswith(f"{external_dir}{os.sep}"):
                return "external-drive"
        return "selected-directory"

    def _log_scan_result(self, scan_result: dict[str, Any], original_path: str, watch_source: str) -> None:
        sandbox_status = get_sandbox_status()
        provider_name = sandbox_status.get("provider_name") or "Quarantine"
        payload = {**current_model_identity(), **dict(scan_result)}
        payload["path"] = str(scan_result.get("path") or "")
        payload["original_path"] = original_path
        payload["watch_source"] = watch_source
        payload["post_action"] = "manual_review_required"
        payload["message"] = (
            f"File was captured from {watch_source} and moved into {provider_name} for review in the app."
        )
        payload["source"] = "directory-monitor"
        payload["overall_result"] = self._decision_to_result(scan_result.get("decision", "UNCERTAIN"))
        write_scan_event(payload)

    def _decision_to_result(self, decision: str) -> str:
        if decision == "BLOCKED":
            return "Malicious"
        if decision == "UNCERTAIN":
            return "Suspicious"
        return "Safe"

    def _process_file(self, path: str) -> None:
        absolute_path = str(Path(path).resolve())
        with self.lock:
            if absolute_path in self.active_files or self._is_in_cooldown(absolute_path):
                return
            self.active_files.add(absolute_path)

        try:
            if is_temporary_download_path(absolute_path) or not os.path.exists(absolute_path):
                return
            if not should_capture_file(absolute_path):
                return

            self._log_action("FILE_DETECTED", absolute_path)
            if not self._wait_for_stable_file(absolute_path):
                return

            file_name = os.path.basename(absolute_path)
            quarantine_target = self._get_unique_destination(self.quarantine_dir, file_name)
            if not self._move_with_retries(absolute_path, quarantine_target):
                self._log_action("MOVE_TO_QUARANTINE_FAILED", absolute_path)
                return

            self.known_file_state.pop(absolute_path, None)
            self._log_action("FILE_MOVED_TO_QUARANTINE", quarantine_target)

            try:
                session = analyze_file_in_native_sandbox(Path(quarantine_target))
                scan_result = _sandbox_managed_scan_result(session.get('scan_result') or {}, quarantine_target, session)
            except Exception as exc:
                scan_result = {
                    "path": quarantine_target,
                    "file_name": file_name,
                    "decision": "UNCERTAIN",
                    "static_prob": 0.5,
                    "behavior_risk": None,
                    "fused_risk": 0.5,
                    "engine": "sandbox_unavailable",
                    "reasons": [],
                    "scanner_stage": None,
                    "scanner_warning": str(exc),
                    "block_threshold": 0.8,
                    "allow_threshold": 0.2,
                    "analysis_origin": "project-sandbox",
                }

            self._log_scan_result(scan_result, absolute_path, self._source_label_for(absolute_path))
        except Exception as exc:
            logging.exception("Processing failed for %s", absolute_path)
            print(f"[ERROR] Processing failed for {absolute_path}: {exc}")
        finally:
            with self.lock:
                self.active_files.discard(absolute_path)
                self._mark_cooldown(absolute_path)

    def _worker_loop(self) -> None:
        while not self.shutdown_requested:
            if not self.running:
                time.sleep(0.2)
                continue
            try:
                file_path = self.file_queue.get(timeout=0.5)
            except Empty:
                continue
            self._process_file(file_path)

    def _report_status(self) -> None:
        sandbox_status = get_sandbox_status()
        provider_name = sandbox_status.get("provider_name") or "Quarantine"
        watch_count = len(self.watch_directories)
        print(f"Monitoring started with {provider_name}.")
        print(f"Watching {watch_count} directories.")
        for directory in self.watch_directories:
            print(f"  - {directory}")
        print(sandbox_status.get("message") or "")

    def start_monitoring(self) -> None:
        if self.running:
            print("Monitoring is already running.")
            return
        self._snapshot_known_files()
        self.running = True
        self._report_status()

    def stop_monitoring(self) -> None:
        if not self.running:
            print("Monitoring is already stopped.")
            return
        self.running = False
        print("Monitoring stopped.")

    def run(self) -> None:
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()

        self.poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.poll_thread.start()

        self.start_monitoring()

        try:
            while not self.shutdown_requested:
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.shutdown_requested = True
        finally:
            self.stop_monitoring()
            if self.worker_thread and self.worker_thread.is_alive():
                self.worker_thread.join(timeout=1)
            if self.poll_thread and self.poll_thread.is_alive():
                self.poll_thread.join(timeout=1)


if __name__ == "__main__":
    app = SandboxDownloadMonitor()
    app.run()
