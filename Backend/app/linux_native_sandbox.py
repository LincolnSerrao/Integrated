from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = PROJECT_ROOT / 'Backend'
SANDBOX_ANALYZER_VENV = BACKEND_ROOT / '.venv-ml'
SANDBOX_ANALYZER_PYTHON = SANDBOX_ANALYZER_VENV / 'bin' / 'python'
STATE_ROOT = (Path.home() / '.local' / 'state' / 'cybershield-project-sandbox').resolve()
HOST_SPAWN_PREFIX = ('flatpak-spawn', '--host')
SESSIONS_DIR = STATE_ROOT / 'sessions'
SESSION_LOG_FILE = STATE_ROOT / 'session_events.jsonl'
PREFERRED_TERMINALS: tuple[tuple[str, list[str]], ...] = (
    ('konsole', ['konsole', '--hold', '-e']),
    ('gnome-terminal', ['gnome-terminal', '--wait', '--']),
    ('xterm', ['xterm', '-hold', '-e']),
)
AUTO_RUN_EXTENSIONS = {'.appimage', '.bin', '.run', '.sh'}


class NativeSandboxError(RuntimeError):
    pass


def _desktop_session_available() -> bool:
    return bool(os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY'))


def _host_spawn_available() -> bool:
    return bool(shutil.which(HOST_SPAWN_PREFIX[0]))


def _which_on_host(command_name: str) -> str | None:
    if not _host_spawn_available():
        return None
    try:
        completed = subprocess.run(
            [*HOST_SPAWN_PREFIX, 'which', command_name],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception:
        return None
    if completed.returncode != 0:
        return None
    resolved = (completed.stdout or '').strip()
    return resolved or None


def _resolve_command_path(command_name: str) -> tuple[str | None, bool]:
    local_path = shutil.which(command_name)
    if local_path:
        return local_path, False
    host_path = _which_on_host(command_name)
    if host_path:
        return host_path, True
    return None, False


def _first_available_command(commands: tuple[tuple[str, list[str]], ...]) -> tuple[str | None, list[str] | None, bool]:
    for name, prefix in commands:
        resolved_path, via_host = _resolve_command_path(name)
        if resolved_path:
            return resolved_path, prefix, via_host
    return None, None, False


def _read_userns_clone_setting() -> int | None:
    value_path = Path('/proc/sys/kernel/unprivileged_userns_clone')
    if not value_path.exists():
        return None
    try:
        return int(value_path.read_text(encoding='utf-8').strip())
    except Exception:
        return None


def _session_event(payload: dict[str, Any]) -> dict[str, Any]:
    event = dict(payload)
    event.setdefault('ts', datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'))
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    with SESSION_LOG_FILE.open('a', encoding='utf-8') as handle:
        handle.write(json.dumps(event) + '\n')
    return event


def get_linux_native_sandbox_status() -> dict[str, Any]:
    firejail_path, firejail_via_host = _resolve_command_path('firejail')
    bwrap_path, bwrap_via_host = _resolve_command_path('bwrap')
    terminal_path, terminal_prefix, terminal_via_host = _first_available_command(PREFERRED_TERMINALS)
    desktop_session = _desktop_session_available()
    userns_clone = _read_userns_clone_setting()

    ready = bool(firejail_path and terminal_prefix and terminal_path and desktop_session)
    if ready:
        message = (
            'Linux Native Sandbox is ready. Captured files can be opened inside a disposable Firejail session '
            'with a private home, private /tmp, and networking disabled by default.'
        )
    elif not desktop_session:
        message = 'Linux Native Sandbox needs a graphical desktop session before it can open an isolated review window.'
    elif not firejail_path:
        message = (
            'Linux Native Sandbox is not installed yet. Install Firejail to get a real non-VM isolation layer '
            'for opening captured files.'
        )
    elif not terminal_prefix:
        message = 'Linux Native Sandbox needs a supported terminal app such as Konsole, GNOME Terminal, or xterm.'
    else:
        message = 'Linux Native Sandbox is not ready.'

    return {
        'provider': 'linux-native-sandbox',
        'provider_name': 'Linux Native Sandbox',
        'ready': ready,
        'supported': bool(firejail_path or bwrap_path),
        'firejail_installed': bool(firejail_path),
        'firejail_path': firejail_path,
        'firejail_via_host': firejail_via_host,
        'bubblewrap_installed': bool(bwrap_path),
        'bubblewrap_path': bwrap_path,
        'bubblewrap_via_host': bwrap_via_host,
        'terminal_name': Path(terminal_path).name if terminal_path else None,
        'terminal_path': terminal_path,
        'terminal_via_host': terminal_via_host,
        'desktop_session': desktop_session,
        'userns_clone_enabled': userns_clone == 1 if userns_clone is not None else None,
        'userns_clone_value': userns_clone,
        'network_default': 'disabled',
        'message': message,
    }


def _prepare_session_dirs(session_id: str) -> dict[str, Path]:
    session_root = SESSIONS_DIR / session_id
    home_dir = session_root / 'home'
    downloads_dir = home_dir / 'Downloads'
    workspace_dir = session_root / 'workspace'
    for directory in (downloads_dir, workspace_dir):
        directory.mkdir(parents=True, exist_ok=True)
    return {
        'session_root': session_root,
        'home_dir': home_dir,
        'downloads_dir': downloads_dir,
        'workspace_dir': workspace_dir,
    }


def _write_session_readme(downloads_dir: Path, sample_name: str) -> Path:
    readme_path = downloads_dir / 'CYBER_SHIELD_SESSION.txt'
    readme_path.write_text(
        '\n'.join([
            'Cyber Shield Isolated Review Session',
            '',
            'This file was copied into a disposable Linux sandbox session.',
            'Network access is disabled by default.',
            'Your normal home, mounted drives, and the project directory are blocked from this session.',
            '',
            f'Sample waiting here: {sample_name}',
            '',
            'If the sample is directly executable, the sandbox terminal will try to launch it once.',
            'If not, you can inspect or run commands manually from the sandbox terminal.',
        ]) + '\n',
        encoding='utf-8',
    )
    return readme_path


def _write_entrypoint(workspace_dir: Path, sample_path: Path) -> Path:
    launcher_path = workspace_dir / 'enter_sandbox.sh'
    should_autorun = sample_path.suffix.lower() in AUTO_RUN_EXTENSIONS
    script = f"""#!/bin/sh
set -eu
cd {str(sample_path.parent)!r}
printf '\nCyber Shield isolated session started.\n'
printf 'Sample path: %s\n' {str(sample_path)!r}
printf 'Network: disabled\n'
printf 'Blocked host areas: /home, /mnt, /media, /run/media, {str(PROJECT_ROOT)!r}\n\n'
ls -la
printf '\n'
if [ {'1' if should_autorun else '0'} -eq 1 ]; then
  chmod u+x {str(sample_path)!r} 2>/dev/null || true
  printf 'Attempting to launch the sample once inside the sandbox...\n\n'
  {str(sample_path)!r} || true
  printf '\nSample process exited. Interactive shell remains open for manual review.\n\n'
else
  printf 'Interactive shell ready. Run the sample manually from this directory if you still want to inspect it.\n\n'
fi
exec /bin/sh
"""
    launcher_path.write_text(script, encoding='utf-8')
    launcher_path.chmod(launcher_path.stat().st_mode | stat.S_IXUSR)
    return launcher_path




def _write_analysis_entrypoint(workspace_dir: Path, analysis_script: Path, sample_path: Path, result_path: Path) -> Path:
    entrypoint_path = workspace_dir / 'run_analysis.sh'
    script = f"""#!/bin/sh
set -eu
. {str(SANDBOX_ANALYZER_VENV / 'bin' / 'activate')!r}
python {str(analysis_script)!r} {str(sample_path)!r} {str(result_path)!r}
"""
    entrypoint_path.write_text(script, encoding='utf-8')
    entrypoint_path.chmod(entrypoint_path.stat().st_mode | stat.S_IXUSR)
    return entrypoint_path


def _write_analysis_script(workspace_dir: Path) -> Path:
    script_path = workspace_dir / 'run_analysis.py'
    script = f"""from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, {str(BACKEND_ROOT)!r})

from app.scanner import scan_file


def main() -> int:
    sample_path = Path(sys.argv[1]).resolve()
    output_path = Path(sys.argv[2]).resolve()
    result = scan_file(sample_path, log_event=False)
    output_path.write_text(json.dumps(result), encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
"""
    script_path.write_text(script, encoding='utf-8')
    return script_path


def _run_analysis_subprocess(status: dict[str, Any], analysis_entrypoint: Path, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    del status
    command = ['/bin/sh', str(analysis_entrypoint)]
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise NativeSandboxError(f'Failed to launch sandbox analyzer: {exc}') from exc
    except subprocess.TimeoutExpired as exc:
        raise NativeSandboxError('Project sandbox analysis timed out') from exc
    except Exception as exc:
        raise NativeSandboxError(f'Project sandbox analysis failed to start: {exc}') from exc


def analyze_file_in_native_sandbox(source_file: Path) -> dict[str, Any]:
    status = get_linux_native_sandbox_status()
    if not status.get('firejail_installed'):
        raise NativeSandboxError(str(status.get('message') or 'Linux Native Sandbox is not ready'))
    if not SANDBOX_ANALYZER_PYTHON.exists():
        raise NativeSandboxError(f'Analyzer Python not found: {SANDBOX_ANALYZER_PYTHON}')

    session_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + uuid4().hex[:8]
    session_dirs = _prepare_session_dirs(session_id)
    sample_copy = session_dirs['downloads_dir'] / source_file.name
    shutil.copy2(source_file, sample_copy)
    _write_session_readme(session_dirs['downloads_dir'], sample_copy.name)
    analysis_script = _write_analysis_script(session_dirs['workspace_dir'])
    result_path = session_dirs['session_root'] / 'analysis_result.json'
    analysis_entrypoint = _write_analysis_entrypoint(session_dirs['workspace_dir'], analysis_script, sample_copy, result_path)

    completed = _run_analysis_subprocess(status, analysis_entrypoint, timeout=300)
    if completed.returncode != 0:
        stderr = (completed.stderr or '').strip()
        stdout = (completed.stdout or '').strip()
        message = stderr or stdout or 'unknown sandbox analysis error'
        raise NativeSandboxError(f'Project sandbox analysis failed: {message}')
    if not result_path.exists():
        raise NativeSandboxError('Project sandbox analysis did not produce a result file')

    try:
        scan_result = json.loads(result_path.read_text(encoding='utf-8'))
    except Exception as exc:
        raise NativeSandboxError(f'Project sandbox analysis returned invalid output: {exc}') from exc

    event = _session_event(
        {
            'session_id': session_id,
            'mode': 'analysis',
            'source_file': str(source_file),
            'sample_copy': str(sample_copy),
            'session_root': str(session_dirs['session_root']),
            'analysis_result_path': str(result_path),
            'network': 'disabled',
            'analysis_engine': scan_result.get('engine'),
            'analysis_runtime': 'flatpak-ml',
        }
    )
    return {
        **event,
        'status': 'analyzed',
        'scan_result': scan_result,
    }

def launch_file_in_native_sandbox(source_file: Path) -> dict[str, Any]:
    status = get_linux_native_sandbox_status()
    if not status.get('ready'):
        raise NativeSandboxError(str(status.get('message') or 'Linux Native Sandbox is not ready'))

    firejail_path = str(status['firejail_path'])
    terminal_prefix = None
    terminal_path = str(status.get('terminal_path') or '')
    terminal_via_host = bool(status.get('terminal_via_host'))
    for name, prefix in PREFERRED_TERMINALS:
        if terminal_path.endswith(name):
            terminal_prefix = prefix
            break
    if not terminal_prefix or not terminal_path:
        raise NativeSandboxError('No supported terminal emulator is available for the native sandbox session')

    session_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + uuid4().hex[:8]
    session_dirs = _prepare_session_dirs(session_id)
    sample_copy = session_dirs['downloads_dir'] / source_file.name
    shutil.copy2(source_file, sample_copy)
    _write_session_readme(session_dirs['downloads_dir'], sample_copy.name)
    launcher_path = _write_entrypoint(session_dirs['workspace_dir'], sample_copy)

    firejail_command = [
        firejail_path,
        '--quiet',
        '--noprofile',
        '--net=none',
        '--private=' + str(session_dirs['home_dir']),
        '--private-tmp',
        '--private-dev',
        '--caps.drop=all',
        '--nonewprivs',
        '--noroot',
        '--seccomp',
        '--blacklist=/home',
        '--blacklist=/mnt',
        '--blacklist=/media',
        '--blacklist=/run/media',
        '--blacklist=' + str(PROJECT_ROOT),
        '/bin/sh',
        str(launcher_path),
    ]
    launch_command = [terminal_path, *terminal_prefix[1:], *firejail_command]
    if terminal_via_host:
        launch_command = [*HOST_SPAWN_PREFIX, *launch_command]

    try:
        process = subprocess.Popen(
            launch_command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        raise NativeSandboxError(f'Failed to launch sandbox terminal: {exc}') from exc
    except Exception as exc:
        raise NativeSandboxError(f'Failed to launch Linux Native Sandbox: {exc}') from exc

    event = _session_event(
        {
            'session_id': session_id,
            'source_file': str(source_file),
            'sample_copy': str(sample_copy),
            'session_root': str(session_dirs['session_root']),
            'pid': process.pid,
            'terminal_name': status.get('terminal_name'),
            'network': 'disabled',
        }
    )
    return {
        **event,
        'status': 'launched',
        'message': 'Linux Native Sandbox launched in a disposable terminal window.',
    }


def _load_session_events() -> list[dict[str, Any]]:
    if not SESSION_LOG_FILE.exists():
        return []
    events: list[dict[str, Any]] = []
    with SESSION_LOG_FILE.open('r', encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            if isinstance(payload, dict):
                events.append(payload)
    return events


def _session_runtime_status(session_root: Path, pid: int | None) -> str:
    if pid:
        try:
            os.kill(int(pid), 0)
            return 'running'
        except Exception:
            pass
    if session_root.exists():
        return 'finished'
    return 'missing'


def _safe_relative_to(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)) or '.'
    except Exception:
        return path.name


def _build_session_tree(root: Path, current: Path | None = None, max_depth: int = 4) -> list[dict[str, Any]]:
    base = root if current is None else current
    if not base.exists() or max_depth < 0:
        return []
    nodes: list[dict[str, Any]] = []
    try:
        entries = sorted(base.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower()))
    except Exception:
        return []
    for entry in entries:
        try:
            stat_result = entry.stat()
        except Exception:
            continue
        node = {
            'name': entry.name,
            'path': _safe_relative_to(entry, root),
            'type': 'directory' if entry.is_dir() else 'file',
            'size_bytes': stat_result.st_size if entry.is_file() else None,
            'modified_at': datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc).isoformat().replace('+00:00', 'Z'),
        }
        if entry.is_dir():
            node['children'] = _build_session_tree(root, entry, max_depth=max_depth - 1)
        nodes.append(node)
    return nodes


def list_native_sandbox_sessions(limit: int = 20) -> list[dict[str, Any]]:
    events = _load_session_events()
    sessions: list[dict[str, Any]] = []
    for event in reversed(events):
        session_id = str(event.get('session_id') or '').strip()
        if not session_id:
            continue
        session_root = Path(str(event.get('session_root') or SESSIONS_DIR / session_id))
        sample_copy = Path(str(event.get('sample_copy') or '')) if event.get('sample_copy') else None
        status = _session_runtime_status(session_root, event.get('pid'))
        sessions.append(
            {
                'session_id': session_id,
                'status': status,
                'source_file': event.get('source_file'),
                'sample_copy': str(sample_copy) if sample_copy else None,
                'sample_name': sample_copy.name if sample_copy else None,
                'session_root': str(session_root),
                'pid': event.get('pid'),
                'terminal_name': event.get('terminal_name'),
                'network': event.get('network') or 'disabled',
                'mode': event.get('mode') or 'interactive',
                'analysis_engine': event.get('analysis_engine'),
                'analysis_runtime': event.get('analysis_runtime') or ('firejail' if event.get('pid') else 'flatpak-ml'),
                'ts': event.get('ts'),
            }
        )
        if len(sessions) >= limit:
            break
    return sessions


def get_native_sandbox_session(session_id: str) -> dict[str, Any] | None:
    safe_id = str(session_id or '').strip()
    if not safe_id:
        return None
    for session in list_native_sandbox_sessions(limit=200):
        if session['session_id'] == safe_id:
            session_root = Path(str(session['session_root']))
            session['tree'] = _build_session_tree(session_root, max_depth=5)
            session['restrictions'] = {
                'network': 'disabled',
                'blocked_paths': ['/mnt', '/media', '/run/media', str(PROJECT_ROOT)] if session.get('mode') == 'analysis' else ['/home', '/mnt', '/media', '/run/media', str(PROJECT_ROOT)],
                'private_home': False if session.get('mode') == 'analysis' else _safe_relative_to(session_root / 'home', session_root),
                'private_tmp': True,
                'caps_dropped': True,
                'no_new_privileges': True,
            }
            result_path = session_root / 'analysis_result.json'
            if result_path.exists():
                try:
                    scan_result = json.loads(result_path.read_text(encoding='utf-8'))
                    session['scan_result'] = scan_result
                    session['decision'] = scan_result.get('decision')
                    session['fused_risk'] = scan_result.get('fused_risk')
                    session['static_prob'] = scan_result.get('static_prob')
                    session['scanner_warning'] = scan_result.get('scanner_warning')
                    session['reasons'] = scan_result.get('reasons') or []
                    session['model_name'] = scan_result.get('model_name') or 'Cyber Shield Zero-Day Detector'
                    session['model_architecture'] = scan_result.get('model_architecture') or 'Feed-Forward Neural Network'
                    session['model_artifact_name'] = scan_result.get('model_artifact_name') or 'cyber_shield_zero_day.pth'
                except Exception:
                    session['scan_result'] = None
            return session
    return None
