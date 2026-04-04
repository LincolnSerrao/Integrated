import os
import sys
import time
import shutil
import logging
import threading
import subprocess
import uuid
import glob
from datetime import datetime
from queue import Queue, Empty
from xml.sax.saxutils import escape
from pathlib import Path

try:
    import pystray
    from PIL import Image, ImageDraw
    HAS_TRAY = True
except Exception:
    HAS_TRAY = False

# Linux paths for Arch Linux KDE
STAGING_DIR = os.environ.get("SANDBOX_STAGING_DIR", "/tmp/cybershield/staging")
SANDBOX_DIR = os.environ.get("SANDBOX_DIR", "/tmp/cybershield/sandbox")
LOG_DIR = os.environ.get("SANDBOX_LOG_DIR", "/tmp/cybershield/logs")
LOG_FILE = os.path.join(LOG_DIR, "sandbox.log")
DOWNLOADS_DIR = os.environ.get("DOWNLOADS_DIR", os.path.expanduser("~/Downloads"))
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_ROOT = os.path.join(PROJECT_ROOT, "Backend")

# Additional download directories to monitor
MONITOR_DIRECTORIES = [
    DOWNLOADS_DIR,
    os.path.expanduser("~/Desktop"),
    "/media/usb",
    "/media/external", 
    "/media/exthdd",
    "/media/windows",
    "/tmp",
    os.path.expanduser("~/.local/share/TelegramDesktop/tdata/user_data"),
    os.path.expanduser("~/.local/share/WhatsApp"),
    os.path.expanduser("~/.var/app/com.discordapp.Discord/data/discord"),
]

# Filter only existing directories
def get_existing_monitor_dirs():
    return [d for d in MONITOR_DIRECTORIES if os.path.exists(d) and os.path.isdir(d)]

KDIALOG_PATH = shutil.which("kdialog")
FIREJAIL_PATH = shutil.which("firejail")
SANDBOX_STARTUP_GRACE_SECONDS = 5
SANDBOX_SHUTDOWN_TIMEOUT_SECONDS = 30
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
    from app.scanner import scan_file, write_scan_event
except Exception as e:
    logging.error(f"Failed to import backend scanner: {e}", exc_info=True)
    print(f"[ERROR] Could not initialize ML Scanner: {e}")
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
        # Only ensure application-specific directories exist
        for path in (STAGING_DIR, SANDBOX_DIR, LOG_DIR):
            os.makedirs(path, exist_ok=True)
        # DOWNLOADS_DIR and others should already exist; we don't force-create system paths.

    def _configure_logging(self):
        os.makedirs(LOG_DIR, exist_ok=True)
        logging.basicConfig(
            filename=LOG_FILE,
            level=logging.INFO,
            format="%(asctime)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

    def _log_action(self, action, path):
        name = Path(path).name or str(path)
        message = "[{0}] {1} {2}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), action, name)
        logging.info(message)
        print(message)

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
            candidate = os.path.join(directory, f"{base}_{index}{ext}")
            index += 1
        return candidate

    def _show_kde_dialog(self, title, message, dialog_type="question"):
        """Show KDE native dialog for user interaction"""
        if not KDIALOG_PATH:
            logging.error("kdialog not found. Cannot show user prompt for: %s", title)
            print(f"[ERROR] kdialog missing. Cannot prompt user for: {title}")
            return False, ""

        try:
            if dialog_type == "warning":
                cmd = ["kdialog", "--warningyesno", message, "--title", title]
            elif dialog_type == "info":
                cmd = ["kdialog", "--msgbox", message, "--title", title]
            elif dialog_type == "file":
                cmd = ["kdialog", "--getsavefilename", os.path.expanduser("~/"), "--title", title]
            else:  # question
                cmd = ["kdialog", "--yesno", message, "--title", title]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0, result.stdout.strip() if result.stdout else ""
        except Exception as exc:
            print(f"[WARN] KDE dialog failed: {exc}")
            return True, ""

    def _preview_file(self, path):
        """Open the file in a firejail sandbox for user review"""
        if not FIREJAIL_PATH:
            self._log_action("SANDBOX_PREVIEW_FALLBACK", path)
            warn_msg = "Firejail is not installed. Opening this file is NOT sandboxed.\n\nDo you want to open it anyway?"
            proceed, _ = self._show_kde_dialog("Security Warning", warn_msg, "warning")
            if not proceed:
                return
            cmd = ["xdg-open", path]
        else:
            self._log_action("SANDBOX_PREVIEW_START", path)
            # Launch firejail with a private profile and no network
            cmd = [FIREJAIL_PATH, "--private", "--net=none", "--quiet", "xdg-open", path]

        try:
            subprocess.run(cmd)
        except FileNotFoundError:
            self._show_kde_dialog("Error", "Could not find a suitable application to open this file type.", "info")
        except Exception as exc:
            print(f"[ERROR] Failed to launch Firejail: {exc}")
            self._log_action("SANDBOX_PREVIEW_FAILED", path)

    def _ask_user_destination(self, file_name):
        """Ask user where to store the file using KDE file dialog"""
        title = f"Select destination for {file_name}"
        success, destination = self._show_kde_dialog(title, "", "file")
        if success and destination:
            return destination
        return os.path.join(DOWNLOADS_DIR, file_name)  # fallback

    def _ask_user_approval(self, file_name, scan_result):
        """Ask user if they want to keep the file based on scan result"""
        decision = scan_result.get("decision", "UNCERTAIN")
        file_path = scan_result.get("file_path", file_name)
        
        preview_requested = False
        
        if decision == "ALLOWED":
            message = f"File '{file_name}' appears to be safe.\n\nScan details:\n- Decision: {decision}\n- Confidence: {scan_result.get('confidence', 'N/A')}\n\nWhere would you like to save this file?"
            success, destination = self._show_kde_dialog("Safe File Detected", message, "file")
            return True, (destination if (success and destination) else os.path.join(DOWNLOADS_DIR, file_name))
        
        # Logic for Malicious or Uncertain files
        is_malicious = (decision == "BLOCKED")
        title = "Malicious Warning" if is_malicious else "Uncertain File"
        prefix = "⚠️ MALICIOUS FILE DETECTED" if is_malicious else "❓ UNCERTAIN FILE"
        prompt = "This file triggered a high-risk alert. Preview in a restricted sandbox?" if is_malicious else "The scan was inconclusive. Preview in sandbox before deciding?"
        
        message = f" {prefix} \n\nFile: {file_name}\n\n{prompt}"
        # Ask to preview
        preview_requested, _ = self._show_kde_dialog(title, message, "warning" if is_malicious else "question")
        
        if preview_requested:
            self._preview_file(file_path)

        # Final choice: Keep or Discard
        keep_msg = "Do you want to keep this file and move it to a safe location?"
        keep, _ = self._show_kde_dialog("Final Decision", keep_msg, "question")
        if keep:
            return True, self._ask_user_destination(file_name)
            
        return False, ""

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
        if decision == "UNCERTAIN" or decision == "Suspicious":
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

    def _snapshot_known_files(self):
        self.known_file_state = {}
        monitor_dirs = get_existing_monitor_dirs()
        monitor_dirs.append(STAGING_DIR)  # Also monitor staging
        
        for monitor_dir in monitor_dirs:
            try:
                for entry in os.scandir(monitor_dir):
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
                print("[WARN] Could not snapshot directory {0}: {1}".format(monitor_dir, exc))

    def _poll_staging_dir(self):
        monitor_dirs = get_existing_monitor_dirs()
        monitor_dirs.append(STAGING_DIR)  # Also monitor staging
        
        all_current_state = {}
        
        for monitor_dir in monitor_dirs:
            try:
                for entry in os.scandir(monitor_dir):
                    if not entry.is_file():
                        continue
                    if is_temporary_download_path(entry.path):
                        continue
                    try:
                        stat = entry.stat()
                    except OSError:
                        continue
                    state = (stat.st_size, stat.st_mtime)
                    all_current_state[entry.path] = state
                    
                    previous_state = self.known_file_state.get(entry.path)
                    if previous_state is None or previous_state != state:
                        with self.lock:
                            if entry.path not in self.active_files and not self._is_in_cooldown(entry.path):
                                self.file_queue.put(entry.path)
            except OSError as exc:
                print("[WARN] Could not poll directory {0}: {1}".format(monitor_dir, exc))
        
        self.known_file_state = all_current_state
        self._prune_cooldowns()

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

        try:
            if is_temporary_download_path(absolute_path):
                return
            if not os.path.exists(absolute_path):
                return

            self._log_action("FILE_DETECTED", absolute_path)

            if not self._wait_for_stable_file(absolute_path):
                return

            file_name = os.path.basename(absolute_path)
            
            # Scan the file first
            scan_result = None
            if scan_file:
                try:
                    scan_result = scan_file(absolute_path, log_event=False)
                    print(f"[INFO] Scan result for {file_name}: {scan_result.get('decision', 'UNKNOWN')}")
                except Exception as exc:
                    print(f"[WARN] Scanner failed for {file_name}: {exc}")
                    scan_result = {"decision": "UNCERTAIN", "confidence": "Low", "error": str(exc)}
            else:
                scan_result = {"decision": "UNCERTAIN", "confidence": "No scanner available"}

            # Ask user what to do based on scan result
            should_save, destination = self._ask_user_approval(file_name, scan_result)
            
            if should_save and destination:
                # Move file to user-selected destination
                final_target = self._get_unique_destination(os.path.dirname(destination), os.path.basename(destination))
                if self._move_with_retries(absolute_path, final_target):
                    self._log_action("USER_APPROVED", final_target)
                    self._log_scan_result(
                        scan_result,
                        "user_approved",
                        f"File approved by user and moved to {final_target}",
                    )
                    print(f"[INFO] File saved to: {final_target}")
                else:
                    print(f"[WARN] Failed to move file to {final_target}")
                    self._log_scan_result(
                        scan_result,
                        "move_failed",
                        f"Failed to move approved file to {final_target}",
                    )
            else:
                # User rejected the file
                self._log_action("USER_REJECTED", absolute_path)
                self._log_scan_result(
                    scan_result,
                    "user_rejected",
                    "File rejected by user",
                )
                print(f"[INFO] File rejected by user: {file_name}")
                # Optionally delete the rejected file
                try:
                    os.remove(absolute_path)
                    print(f"[INFO] Rejected file deleted: {absolute_path}")
                except Exception as exc:
                    print(f"[WARN] Failed to delete rejected file: {exc}")

            self.known_file_state.pop(absolute_path, None)

        except Exception as exc:
            print(f"[ERROR] Processing failed for {absolute_path}: {exc}")
            logging.exception("Processing failed for %s", absolute_path)
        finally:
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

    def start_monitoring(self):
        if self.running:
            print("Monitoring is already running.")
            return
        self._snapshot_known_files()
        self.running = True
        monitor_dirs = get_existing_monitor_dirs()
        monitor_dirs.append(STAGING_DIR)
        print(f"Monitoring started for {len(monitor_dirs)} directories:")
        for directory in monitor_dirs:
            print(f"  - {directory}")

    def stop_monitoring(self):
        if not self.running:
            print("Monitoring is already stopped.")
            return
        self.running = False

        print("Monitoring stopped.")

    def run(self):
        if not KDIALOG_PATH:
            print("[ERROR] kdialog not found! User prompts will fail on Arch KDE.")
            logging.error("kdialog missing from system path.")

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
