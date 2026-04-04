import os
import sys
import time
import shutil
import logging
import threading
import subprocess
import uuid
from datetime import datetime
from queue import Queue, Empty
from xml.sax.saxutils import escape

try:
    import pystray
    from PIL import Image, ImageDraw
    HAS_TRAY = True
except Exception:
    HAS_TRAY = False

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_STAGING_DIR = r"D:\Download"
FALLBACK_STAGING_DIR = os.path.join(PROJECT_ROOT, "staging", "Download")
STAGING_DIR = os.environ.get("SANDBOX_STAGING_DIR", DEFAULT_STAGING_DIR)
SANDBOX_DIR = r"C:\Sandbox_VM_Input"
LOG_DIR = r"C:\Sandbox_Logs"
LOG_FILE = os.path.join(LOG_DIR, "sandbox.log")
DOWNLOADS_DIR = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\Public"), "Downloads")
BACKEND_ROOT = os.path.join(PROJECT_ROOT, "Backend")

SANDBOX_SESSION_ROOT = os.path.join(SANDBOX_DIR, "sessions")
SANDBOX_GUEST_MOUNT_DIR = r"C:\HostShare"
SANDBOX_GUEST_IN_DIR = SANDBOX_GUEST_MOUNT_DIR + r"\in"
SANDBOX_GUEST_OUT_DIR = SANDBOX_GUEST_MOUNT_DIR + r"\out"
SANDBOX_STARTUP_GRACE_SECONDS = 5
SANDBOX_RELEASE_WAIT_SECONDS = 1800
SANDBOX_SHUTDOWN_TIMEOUT_SECONDS = 30
VIRTUALBOX_STARTUP_TIMEOUT_SECONDS = 90
VIRTUALBOX_POLL_INTERVAL_SECONDS = 2
VIRTUALBOX_VM_START_TYPE = os.environ.get("VIRTUALBOX_VM_START_TYPE", "gui")
VIRTUALBOX_STOP_MODE = os.environ.get("VIRTUALBOX_STOP_MODE", "acpipowerbutton").strip().lower()
SESSION_CLEANUP_RETRIES = 5

POLL_INTERVAL_SECONDS = 2
STABLE_CHECK_INTERVAL_SECONDS = 1.0
STABLE_CHECK_ROUNDS = 5
STABLE_WAIT_TIMEOUT_SECONDS = 300
LOCK_RETRY_DELAY_SECONDS = 1.0
MAX_LOCK_RETRIES = 10
PROCESS_COOLDOWN_SECONDS = 15
TEMP_DOWNLOAD_EXTENSIONS = (".crdownload", ".part", ".tmp", ".download")
IGNORED_FILE_NAMES = {
    "desktop.ini",
    "thumbs.db",
}

if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)

try:
    from app.sandbox_status import (
        get_configured_sandbox_provider,
        get_sandbox_provider_name,
        get_sandbox_status,
        get_virtualbox_guest_session_path,
        get_virtualbox_vm_name,
        resolve_vboxmanage_exe,
        resolve_windows_sandbox_exe,
    )
    from app.scanner import scan_file, write_scan_event
except Exception:
    get_configured_sandbox_provider = None
    get_sandbox_provider_name = None
    get_sandbox_status = None
    get_virtualbox_guest_session_path = None
    get_virtualbox_vm_name = None
    resolve_vboxmanage_exe = None
    resolve_windows_sandbox_exe = None
    scan_file = None
    write_scan_event = None


def is_temporary_download_path(path):
    lower = path.lower()
    name = os.path.basename(lower)
    if name in IGNORED_FILE_NAMES:
        return True
    if name.startswith("unconfirmed"):
        return True
    if name.startswith("~$"):
        return True
    for ext in TEMP_DOWNLOAD_EXTENSIONS:
        if lower.endswith(ext):
            return True
    return False


def env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


class SandboxDownloadMonitor(object):
    def __init__(self):
        self.running = False
        self.shutdown_requested = False
        self.file_queue = Queue()
        self.worker_thread = None
        self.poll_thread = None
        self.lock = threading.Lock()
        self.active_files = set()
        self.recently_processed = {}
        self.current_sandbox_process = None
        self.known_file_state = {}
        self.tray_icon = None

        self._ensure_directories()
        self._configure_logging()

    def _ensure_directories(self):
        self._ensure_staging_dir()
        for path in (STAGING_DIR, SANDBOX_DIR, SANDBOX_SESSION_ROOT, LOG_DIR, DOWNLOADS_DIR):
            os.makedirs(path, exist_ok=True)

    def _ensure_staging_dir(self):
        global STAGING_DIR
        try:
            os.makedirs(STAGING_DIR, exist_ok=True)
        except OSError:
            STAGING_DIR = FALLBACK_STAGING_DIR
            os.makedirs(STAGING_DIR, exist_ok=True)

    def _configure_logging(self):
        os.makedirs(LOG_DIR, exist_ok=True)
        logging.basicConfig(
            filename=LOG_FILE,
            level=logging.INFO,
            format="%(asctime)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

    def _log_action(self, action, path):
        name = os.path.basename(path.rstrip("\\")) or path
        message = "[{0}] {1} {2}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), action, name)
        logging.info(message)
        print(message)

    def _provider(self):
        if get_configured_sandbox_provider:
            try:
                return get_configured_sandbox_provider()
            except Exception:
                pass
        return "windows-sandbox"

    def _provider_name(self):
        if get_sandbox_provider_name:
            try:
                return get_sandbox_provider_name(self._provider())
            except Exception:
                pass
        if self._provider() == "virtualbox":
            return "VirtualBox"
        return "Windows Sandbox"

    def _parse_vbox_machine_output(self, output):
        values = {}
        for line in str(output or "").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"')
        return values

    def _get_virtualbox_vm_info(self, vm_name):
        manage_exe = None
        if resolve_vboxmanage_exe:
            manage_exe, _ = resolve_vboxmanage_exe()
        if not manage_exe:
            return None, "VBoxManage.exe was not found."

        try:
            completed = subprocess.run(
                [manage_exe, "showvminfo", vm_name, "--machinereadable"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return None, "VBoxManage timed out while querying the VM."
        except Exception as exc:
            return None, "VBoxManage failed while querying the VM: {0}".format(exc)

        output = (completed.stdout or completed.stderr or "").strip()
        if completed.returncode != 0:
            return None, output or "VBoxManage exited with code {0}".format(completed.returncode)

        return self._parse_vbox_machine_output(output), None

    def _prune_cooldowns(self):
        now = time.time()
        expired = [path for path, expiry in self.recently_processed.items() if expiry <= now]
        for path in expired:
            self.recently_processed.pop(path, None)

    def _is_in_cooldown(self, path):
        expiry = self.recently_processed.get(path)
        if expiry is None:
            return False
        if expiry <= time.time():
            self.recently_processed.pop(path, None)
            return False
        return True

    def _mark_cooldown(self, path):
        self.recently_processed[path] = time.time() + PROCESS_COOLDOWN_SECONDS

    def _wait_for_stable_file(self, path):
        same_count = 0
        previous_size = -1
        previous_mtime = -1.0
        start_time = time.time()

        while self.running and not self.shutdown_requested:
            if not os.path.exists(path):
                print("[WARN] File disappeared while waiting for stability: {0}".format(path))
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
                    print("[INFO] File became stable: {0}".format(path))
                    return True
            else:
                same_count = 0
                previous_size = current_size
                previous_mtime = current_mtime

            if time.time() - start_time > STABLE_WAIT_TIMEOUT_SECONDS:
                print("[WARN] Timed out waiting for file to stabilize: {0}".format(path))
                self._log_action("FILE_STABILITY_TIMEOUT", path)
                return False

            time.sleep(STABLE_CHECK_INTERVAL_SECONDS)

        return False

    def _move_with_retries(self, src, dst):
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

    def _rmtree_with_retries(self, path):
        if not os.path.exists(path):
            return True

        attempt = 0
        while attempt < SESSION_CLEANUP_RETRIES:
            try:
                shutil.rmtree(path)
                return True
            except (PermissionError, OSError):
                attempt += 1
                time.sleep(LOCK_RETRY_DELAY_SECONDS)
        return False

    def _get_unique_destination(self, directory, file_name):
        base, ext = os.path.splitext(file_name)
        candidate = os.path.join(directory, file_name)
        index = 1
        while os.path.exists(candidate):
            candidate = os.path.join(directory, "{0} ({1}){2}".format(base, index, ext))
            index += 1
        return candidate

    def _build_session(self, file_name):
        session_id = "{0}_{1}".format(datetime.now().strftime("%Y%m%d_%H%M%S"), uuid.uuid4().hex[:8])
        session_dir = os.path.join(SANDBOX_SESSION_ROOT, session_id)
        host_in_dir = os.path.join(session_dir, "in")
        host_out_dir = os.path.join(session_dir, "out")
        os.makedirs(host_in_dir, exist_ok=True)
        os.makedirs(host_out_dir, exist_ok=True)

        safe_file_name = os.path.basename(file_name)
        host_in_file = os.path.join(host_in_dir, safe_file_name)
        host_out_file = os.path.join(host_out_dir, safe_file_name)
        wsb_path = os.path.join(session_dir, "sandbox.wsb")
        init_cmd_path = os.path.join(session_dir, "sandbox_init.cmd")
        review_notes_path = os.path.join(session_dir, "review_instructions.txt")
        guest_session_dir = None
        guest_in_dir = SANDBOX_GUEST_IN_DIR
        guest_out_dir = SANDBOX_GUEST_OUT_DIR

        if self._provider() == "virtualbox" and get_virtualbox_guest_session_path:
            try:
                guest_session_dir = get_virtualbox_guest_session_path(session_id)
            except Exception:
                guest_session_dir = None
            if guest_session_dir:
                guest_in_dir = os.path.join(guest_session_dir, "in")
                guest_out_dir = os.path.join(guest_session_dir, "out")

        return {
            "id": session_id,
            "dir": session_dir,
            "host_in_dir": host_in_dir,
            "host_out_dir": host_out_dir,
            "host_in_file": host_in_file,
            "host_out_file": host_out_file,
            "wsb_path": wsb_path,
            "init_cmd_path": init_cmd_path,
            "review_notes_path": review_notes_path,
            "file_name": safe_file_name,
            "guest_session_dir": guest_session_dir,
            "guest_in_dir": guest_in_dir,
            "guest_out_dir": guest_out_dir,
        }

    def _write_session_files(self, session):
        if self._provider() == "virtualbox":
            instructions = (
                "Cyber Shield Sandbox Review\r\n"
                "Provider: {0}\r\n"
                "Session: {1}\r\n"
                "\r\n"
                "Open this folder inside the guest VM:\r\n"
                "{2}\r\n"
                "\r\n"
                "Input file:\r\n"
                "{3}\\{4}\r\n"
                "\r\n"
                "Approve the file by moving it into:\r\n"
                "{5}\r\n"
                "\r\n"
                "Reject the file by deleting it from:\r\n"
                "{3}\r\n"
            ).format(
                self._provider_name(),
                session["id"],
                session.get("guest_session_dir") or session["dir"],
                session["guest_in_dir"],
                session["file_name"],
                session["guest_out_dir"],
            )
            with open(session["review_notes_path"], "w", encoding="utf-8") as handle:
                handle.write(instructions)
            return

        init_cmd = (
            "@echo off\r\n"
            "title Sandbox Session\r\n"
            "if not exist \"{0}\" mkdir \"{0}\"\r\n"
            "echo Sandbox session started.\r\n"
            "echo Input file path: {1}\\{2}\r\n"
            "echo To approve, move file to: {3}\r\n"
            "echo To reject, delete file from: {1}\r\n"
            "start \"\" explorer.exe \"{1}\"\r\n"
        ).format(
            session["guest_out_dir"],
            session["guest_in_dir"],
            session["file_name"],
            session["guest_out_dir"],
        )
        with open(session["init_cmd_path"], "w", encoding="utf-8") as handle:
            handle.write(init_cmd)

        wsb_contents = (
            "<Configuration>\n"
            "  <MappedFolders>\n"
            "    <MappedFolder>\n"
            "      <HostFolder>{0}</HostFolder>\n"
            "      <SandboxFolder>{1}</SandboxFolder>\n"
            "      <ReadOnly>false</ReadOnly>\n"
            "    </MappedFolder>\n"
            "  </MappedFolders>\n"
            "  <LogonCommand>\n"
            "    <Command>{2}</Command>\n"
            "  </LogonCommand>\n"
            "</Configuration>\n"
        ).format(
            escape(session["dir"]),
            escape(SANDBOX_GUEST_MOUNT_DIR),
            escape(SANDBOX_GUEST_MOUNT_DIR + r"\sandbox_init.cmd"),
        )
        with open(session["wsb_path"], "w", encoding="utf-8") as handle:
            handle.write(wsb_contents)

    def _launch_windows_sandbox(self, session):
        sandbox_exe = None
        if resolve_windows_sandbox_exe:
            sandbox_exe, _ = resolve_windows_sandbox_exe()
        if not sandbox_exe:
            print("[ERROR] Windows Sandbox executable not found. Checked System32 and WinSxS locations.")
            return None
        try:
            process = subprocess.Popen([sandbox_exe, session["wsb_path"]])
        except Exception as exc:
            print("[ERROR] Failed to launch Windows Sandbox using {0}: {1}".format(sandbox_exe, exc))
            return None

        time.sleep(SANDBOX_STARTUP_GRACE_SECONDS)
        if process.poll() is not None:
            print(
                "[ERROR] Windows Sandbox exited immediately from {0} with code {1}".format(
                    sandbox_exe,
                    process.returncode,
                )
            )
            return None

        handle = {
            "provider": "windows-sandbox",
            "process": process,
        }
        self.current_sandbox_process = handle
        print("[INFO] Windows Sandbox launched from: {0}".format(sandbox_exe))
        self._log_action("SANDBOX_STARTED", session["id"])
        return handle

    def _launch_virtualbox_sandbox(self, session):
        manage_exe = None
        if resolve_vboxmanage_exe:
            manage_exe, _ = resolve_vboxmanage_exe()
        if not manage_exe:
            print("[ERROR] VBoxManage.exe was not found.")
            return

        vm_name = ""
        if get_virtualbox_vm_name:
            try:
                vm_name = get_virtualbox_vm_name()
            except Exception:
                vm_name = ""
        if not vm_name:
            print("[ERROR] VIRTUALBOX_VM_NAME is not configured.")
            return None

        info, error = self._get_virtualbox_vm_info(vm_name)
        if not info:
            print("[ERROR] Could not query VirtualBox VM '{0}': {1}".format(vm_name, error))
            return None

        started_here = False
        if info.get("VMState") != "running":
            try:
                completed = subprocess.run(
                    [manage_exe, "startvm", vm_name, "--type", VIRTUALBOX_VM_START_TYPE],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
            except Exception as exc:
                print("[ERROR] Failed to start VirtualBox VM '{0}': {1}".format(vm_name, exc))
                return None

            if completed.returncode != 0:
                detail = (completed.stdout or completed.stderr or "").strip()
                print("[ERROR] VBoxManage could not start '{0}': {1}".format(vm_name, detail))
                return None

            started_here = True

        deadline = time.time() + VIRTUALBOX_STARTUP_TIMEOUT_SECONDS
        last_state = info.get("VMState") or "unknown"
        while time.time() < deadline:
            info, error = self._get_virtualbox_vm_info(vm_name)
            if info:
                last_state = info.get("VMState") or last_state
                if last_state == "running":
                    handle = {
                        "provider": "virtualbox",
                        "vm_name": vm_name,
                        "started_here": started_here,
                    }
                    self.current_sandbox_process = handle
                    print("[INFO] VirtualBox VM ready: {0}".format(vm_name))
                    self._log_action("SANDBOX_STARTED", session["id"])
                    return handle
            time.sleep(VIRTUALBOX_POLL_INTERVAL_SECONDS)

        print(
            "[ERROR] VirtualBox VM '{0}' did not reach running state within {1} seconds (last state: {2}).".format(
                vm_name,
                VIRTUALBOX_STARTUP_TIMEOUT_SECONDS,
                last_state,
            )
        )
        return None

    def _launch_sandbox(self, session):
        if self._provider() == "virtualbox":
            return self._launch_virtualbox_sandbox(session)
        return self._launch_windows_sandbox(session)

    def _shutdown_windows_sandbox(self, handle, session_id):
        if not handle:
            return

        process = handle.get("process") if isinstance(handle, dict) else handle
        if not process:
            return
        if process.poll() is not None:
            self._log_action("SANDBOX_STOPPED", session_id)
            return

        try:
            process.terminate()
            process.wait(timeout=SANDBOX_SHUTDOWN_TIMEOUT_SECONDS)
        except Exception:
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=SANDBOX_SHUTDOWN_TIMEOUT_SECONDS,
                )
            except Exception:
                pass

        self._log_action("SANDBOX_STOPPED", session_id)

    def _shutdown_virtualbox_sandbox(self, handle, session_id):
        if not handle:
            return

        vm_name = handle.get("vm_name")
        started_here = bool(handle.get("started_here"))
        if not vm_name:
            return

        if not started_here or env_flag("VIRTUALBOX_KEEP_RUNNING", False):
            self._log_action("SANDBOX_STOPPED", session_id)
            return

        manage_exe = None
        if resolve_vboxmanage_exe:
            manage_exe, _ = resolve_vboxmanage_exe()
        if not manage_exe:
            self._log_action("SANDBOX_STOPPED", session_id)
            return

        command = ["controlvm", vm_name, "acpipowerbutton"]
        if VIRTUALBOX_STOP_MODE == "poweroff":
            command = ["controlvm", vm_name, "poweroff"]
        elif VIRTUALBOX_STOP_MODE == "savestate":
            command = ["controlvm", vm_name, "savestate"]

        try:
            subprocess.run(
                [manage_exe] + command,
                capture_output=True,
                text=True,
                timeout=SANDBOX_SHUTDOWN_TIMEOUT_SECONDS,
                check=False,
            )
        except Exception:
            pass

        if VIRTUALBOX_STOP_MODE == "acpipowerbutton":
            deadline = time.time() + SANDBOX_SHUTDOWN_TIMEOUT_SECONDS
            while time.time() < deadline:
                info, _ = self._get_virtualbox_vm_info(vm_name)
                if not info or info.get("VMState") != "running":
                    break
                time.sleep(1)

        self._log_action("SANDBOX_STOPPED", session_id)

    def _shutdown_sandbox(self, handle, session_id):
        if not handle:
            return
        provider = handle.get("provider") if isinstance(handle, dict) else "windows-sandbox"
        if provider == "virtualbox":
            self._shutdown_virtualbox_sandbox(handle, session_id)
            return
        self._shutdown_windows_sandbox(handle, session_id)

    def _wait_for_file_removed(self, path, timeout_seconds):
        start_time = time.time()
        while self.running and not self.shutdown_requested:
            if not os.path.exists(path):
                return True
            if time.time() - start_time > timeout_seconds:
                return False
            time.sleep(0.5)
        return not os.path.exists(path)

    def _decision_to_result(self, decision):
        if decision == "BLOCKED":
            return "Malicious"
        if decision == "UNCERTAIN":
            return "Suspicious"
        return "Safe"

    def _log_scan_result(self, scan_result, post_action, message):
        if not write_scan_event:
            return

        payload = dict(scan_result)
        payload["post_action"] = post_action
        payload["message"] = message
        payload["source"] = "download-monitor"
        payload["overall_result"] = self._decision_to_result(scan_result.get("decision", "UNCERTAIN"))
        write_scan_event(payload)

    def _get_sandbox_status(self):
        if not get_sandbox_status:
            return None
        try:
            return get_sandbox_status()
        except Exception as exc:
            print("[WARN] Could not read sandbox status: {0}".format(exc))
            return None

    def _snapshot_known_files(self):
        self.known_file_state = {}
        try:
            for entry in os.scandir(STAGING_DIR):
                if not entry.is_file():
                    continue
                if is_temporary_download_path(entry.path):
                    continue
                try:
                    stat = entry.stat()
                except OSError:
                    continue
                self.known_file_state[entry.path] = (stat.st_size, stat.st_mtime)
        except OSError as exc:
            print("[WARN] Could not snapshot staging folder: {0}".format(exc))

    def _poll_staging_dir(self):
        try:
            current_state = {}
            for entry in os.scandir(STAGING_DIR):
                if not entry.is_file():
                    continue
                if is_temporary_download_path(entry.path):
                    continue
                try:
                    stat = entry.stat()
                except OSError:
                    continue
                state = (stat.st_size, stat.st_mtime)
                current_state[entry.path] = state
                previous_state = self.known_file_state.get(entry.path)
                if previous_state is None or previous_state != state:
                    with self.lock:
                        if entry.path not in self.active_files and not self._is_in_cooldown(entry.path):
                            self.file_queue.put(entry.path)
            self.known_file_state = current_state
            self._prune_cooldowns()
        except OSError as exc:
            print("[WARN] Could not poll staging folder: {0}".format(exc))

    def _poll_loop(self):
        while not self.shutdown_requested:
            if self.running:
                self._poll_staging_dir()
            time.sleep(POLL_INTERVAL_SECONDS)

    def _process_file(self, path):
        absolute_path = os.path.abspath(path)
        with self.lock:
            if absolute_path in self.active_files:
                return
            if self._is_in_cooldown(absolute_path):
                return
            self.active_files.add(absolute_path)

        session = None
        sandbox_process = None
        scan_result = None

        try:
            if is_temporary_download_path(absolute_path):
                return
            if not os.path.exists(absolute_path):
                return

            self._log_action("FILE_DETECTED", absolute_path)

            if not self._wait_for_stable_file(absolute_path):
                return

            file_name = os.path.basename(absolute_path)
            sandbox_status = self._get_sandbox_status()

            if sandbox_status and not sandbox_status.get("ready"):
                if scan_file:
                    try:
                        scan_result = scan_file(absolute_path, log_event=False)
                    except Exception as exc:
                        print("[WARN] Scanner failed for {0}: {1}".format(file_name, exc))
                        scan_result = None

                self._log_action("SANDBOX_UNAVAILABLE", file_name)
                if scan_result:
                    self._log_scan_result(
                        scan_result,
                        "app_review_required",
                        (
                            "{0} File remains in protected staging for review in the app."
                            .format(sandbox_status.get("message") or "")
                        ).strip(),
                    )
                return

            session = self._build_session(file_name)
            self._write_session_files(session)

            if not self._move_with_retries(absolute_path, session["host_in_file"]):
                print("[WARN] Could not move file into sandbox session: {0}".format(file_name))
                return
            self._log_action("FILE_MOVED_TO_SANDBOX", session["host_in_file"])
            self.known_file_state.pop(absolute_path, None)

            if scan_file:
                try:
                    scan_result = scan_file(session["host_in_file"], log_event=False)
                except Exception as exc:
                    print("[WARN] Scanner failed for {0}: {1}".format(file_name, exc))
                    scan_result = None

            sandbox_process = self._launch_sandbox(session)
            if not sandbox_process:
                self._log_action("SANDBOX_LAUNCH_FAILED", file_name)
                if scan_result:
                    status_message = "{0} could not be launched on this machine.".format(self._provider_name())
                    if sandbox_status is None and get_sandbox_status:
                        sandbox_status = self._get_sandbox_status()
                    if sandbox_status:
                        status_message = str(sandbox_status.get("message") or status_message)
                    self._log_scan_result(
                        scan_result,
                        "sandbox_launch_failed",
                        status_message,
                    )
                recovery_target = self._get_unique_destination(STAGING_DIR, file_name)
                self._move_with_retries(session["host_in_file"], recovery_target)
                return

            if scan_result:
                self._log_scan_result(
                    scan_result,
                    "manual_review_required",
                    "File was moved into {0} and scanned there. Review it inside the sandbox session.".format(
                        self._provider_name()
                    ),
                )

            print("[INFO] {0} action required for: {1}".format(self._provider_name(), file_name))
            print("[INFO] Approve by moving file to '{0}', reject by deleting from '{1}'.".format(
                session["guest_out_dir"],
                session["guest_in_dir"],
            ))

            removed = self._wait_for_file_removed(session["host_in_file"], SANDBOX_RELEASE_WAIT_SECONDS)
            if not removed:
                print("[WARN] Timed out waiting for file removal in {0}: {1}".format(self._provider_name(), file_name))
            else:
                self._log_action("FILE_REMOVED_FROM_SANDBOX", session["host_in_file"])

            if os.path.exists(session["host_out_file"]):
                final_target = self._get_unique_destination(DOWNLOADS_DIR, file_name)
                if self._move_with_retries(session["host_out_file"], final_target):
                    self._log_action("USER_ALLOWED", final_target)
                    if scan_result:
                        self._log_scan_result(
                            scan_result,
                            "user_allowed",
                            "User approved the file in {0} and it was restored to Downloads.".format(
                                self._provider_name()
                            ),
                        )
                else:
                    print("[WARN] Failed to move approved file to Downloads: {0}".format(file_name))
            elif removed:
                self._log_action("USER_REJECTED", file_name)
                if scan_result:
                    self._log_scan_result(
                        scan_result,
                        "user_rejected",
                        "User rejected the file in {0} and it was not restored to Downloads.".format(
                            self._provider_name()
                        ),
                    )

        except Exception as exc:
            print("[ERROR] Processing failed for {0}: {1}".format(absolute_path, exc))
            logging.exception("Processing failed for %s", absolute_path)
        finally:
            if session:
                self._shutdown_sandbox(sandbox_process, session["id"])
                self.current_sandbox_process = None
                if not self._rmtree_with_retries(session["dir"]):
                    print("[WARN] Failed to clean sandbox session directory: {0}".format(session["dir"]))

            with self.lock:
                self.active_files.discard(absolute_path)
                self._mark_cooldown(absolute_path)

    def _worker_loop(self):
        while not self.shutdown_requested:
            if not self.running:
                time.sleep(0.2)
                continue
            try:
                file_path = self.file_queue.get(timeout=0.5)
            except Empty:
                continue
            self._process_file(file_path)

    def _create_icon_image(self):
        image = Image.new("RGB", (64, 64), color=(24, 68, 92))
        draw = ImageDraw.Draw(image)
        draw.rectangle((16, 16, 48, 48), fill=(120, 220, 160))
        draw.rectangle((24, 24, 40, 40), fill=(24, 68, 92))
        return image

    def _start_from_tray(self, icon, item):
        self.start_monitoring()

    def _stop_from_tray(self, icon, item):
        self.stop_monitoring()

    def _exit_from_tray(self, icon, item):
        self.shutdown_requested = True
        self.stop_monitoring()
        icon.stop()

    def _start_tray(self):
        image = self._create_icon_image()
        menu = pystray.Menu(
            pystray.MenuItem("Start Monitoring", self._start_from_tray),
            pystray.MenuItem("Stop Monitoring", self._stop_from_tray),
            pystray.MenuItem("Exit", self._exit_from_tray),
        )
        self.tray_icon = pystray.Icon("SandboxMonitor", image, "Sandbox Monitor", menu)
        self.tray_icon.run_detached()
        print("Tray icon started.")

    def _report_sandbox_status(self):
        if not get_sandbox_status:
            print("[WARN] Sandbox status helper could not be imported.")
            return

        status = self._get_sandbox_status()
        if not status:
            print("[WARN] Sandbox status is unavailable.")
            return

        provider_name = status.get("provider_name") or self._provider_name()
        if status.get("ready"):
            target = status.get("vm_name") or status.get("executable_path") or status.get("guest_base_path")
            print("[INFO] {0} is available: {1}".format(provider_name, target))
            return

        print("[WARN] {0} is unavailable: {1}".format(provider_name, status.get("message")))

    def start_monitoring(self):
        if self.running:
            print("Monitoring is already running.")
            return
        self._snapshot_known_files()
        self.running = True
        print("Monitoring started: {0}".format(STAGING_DIR))
        self._report_sandbox_status()

    def stop_monitoring(self):
        if not self.running:
            print("Monitoring is already stopped.")
            return
        self.running = False

        if self.current_sandbox_process:
            self._shutdown_sandbox(self.current_sandbox_process, "active_session")
            self.current_sandbox_process = None

        print("Monitoring stopped.")

    def run(self):
        self.worker_thread = threading.Thread(target=self._worker_loop)
        self.worker_thread.daemon = True
        self.worker_thread.start()

        self.poll_thread = threading.Thread(target=self._poll_loop)
        self.poll_thread.daemon = True
        self.poll_thread.start()

        self.start_monitoring()

        if HAS_TRAY:
            self._start_tray()
        else:
            print("Tray dependencies not installed. Running without tray icon.")

        try:
            while not self.shutdown_requested:
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.shutdown_requested = True
        finally:
            self.stop_monitoring()
            if self.tray_icon:
                try:
                    self.tray_icon.stop()
                except Exception:
                    pass
            if self.worker_thread and self.worker_thread.is_alive():
                self.worker_thread.join(timeout=1)
            if self.poll_thread and self.poll_thread.is_alive():
                self.poll_thread.join(timeout=1)


if __name__ == "__main__":
    app = SandboxDownloadMonitor()
    app.run()
