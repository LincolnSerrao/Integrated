from __future__ import annotations

import glob
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

try:
    import winreg
except Exception:  # pragma: no cover - Windows-only helper
    winreg = None


SYSTEM32_SANDBOX_EXE = Path(r"C:\Windows\System32\WindowsSandbox.exe")
WINSXS_PATTERNS = (
    r"C:\Windows\WinSxS\*\WindowsSandbox.exe",
    r"C:\Windows\WinSxS\*\WindowsSandboxClient.exe",
)
CURRENT_VERSION_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
WINDOWS_11_BUILD_FLOOR = 22000
DEFAULT_SANDBOX_PROVIDER = "windows-sandbox"
VIRTUALBOX_PROVIDER = "virtualbox"
WINDOWS_SANDBOX_PROVIDER = "windows-sandbox"
COMMON_VBOXMANAGE_PATHS = (
    Path(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"),
    Path(r"C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe"),
)
VIRTUALBOX_GLOBAL_CONFIG = Path.home() / ".VirtualBox" / "VirtualBox.xml"


def _read_current_version_value(name: str) -> str | None:
    if winreg is None:
        return None

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CURRENT_VERSION_KEY) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return str(value)
    except Exception:
        return None


def _windows_identity() -> dict[str, Any]:
    product_name = _read_current_version_value("ProductName")
    edition_id = _read_current_version_value("EditionID")
    display_version = _read_current_version_value("DisplayVersion")
    build_raw = _read_current_version_value("CurrentBuild")

    build_number: int | None = None
    if build_raw:
        try:
            build_number = int(build_raw)
        except ValueError:
            build_number = None

    family = "Windows 11" if (build_number or 0) >= WINDOWS_11_BUILD_FLOOR else "Windows 10"

    edition_label_map = {
        "Core": "Home",
        "Professional": "Pro",
        "Enterprise": "Enterprise",
        "Education": "Education",
        "ProfessionalEducation": "Pro Education",
        "ProfessionalWorkstation": "Pro for Workstations",
    }
    edition_label = edition_label_map.get(edition_id or "", edition_id)

    normalized_name = family
    if edition_label:
        normalized_name = f"{family} {edition_label}"
    elif product_name:
        normalized_name = product_name

    return {
        "product_name": product_name,
        "normalized_name": normalized_name,
        "edition_id": edition_id,
        "display_version": display_version,
        "build_number": build_number,
    }


def _normalize_provider_name(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    aliases = {
        "windows": WINDOWS_SANDBOX_PROVIDER,
        "windows_sandbox": WINDOWS_SANDBOX_PROVIDER,
        "windowssandbox": WINDOWS_SANDBOX_PROVIDER,
        "virtual-box": VIRTUALBOX_PROVIDER,
        "virtual_box": VIRTUALBOX_PROVIDER,
        "vbox": VIRTUALBOX_PROVIDER,
    }
    return aliases.get(normalized, normalized or DEFAULT_SANDBOX_PROVIDER)


def get_configured_sandbox_provider() -> str:
    explicit = os.environ.get("SANDBOX_PROVIDER")
    if explicit:
        return _normalize_provider_name(explicit)

    if get_virtualbox_vm_name():
        return VIRTUALBOX_PROVIDER

    return DEFAULT_SANDBOX_PROVIDER


def get_sandbox_provider_name(provider: str | None = None) -> str:
    resolved = _normalize_provider_name(provider or get_configured_sandbox_provider())
    if resolved == VIRTUALBOX_PROVIDER:
        return "VirtualBox"
    return "Windows Sandbox"


def resolve_windows_sandbox_exe() -> tuple[str | None, str | None]:
    env_override = os.environ.get("WINDOWS_SANDBOX_EXE")
    if env_override and os.path.exists(env_override):
        return env_override, "env"

    if SYSTEM32_SANDBOX_EXE.exists():
        return str(SYSTEM32_SANDBOX_EXE), "system32"

    matches: list[str] = []
    for pattern in WINSXS_PATTERNS:
        matches.extend(glob.glob(pattern))

    if matches:
        matches.sort(reverse=True)
        return matches[0], "winsxs"

    return None, None


def get_windows_sandbox_status() -> dict[str, Any]:
    identity = _windows_identity()
    product_name = identity["normalized_name"]
    exe_path, source = resolve_windows_sandbox_exe()
    is_windows = os.name == "nt"
    edition_id = str(identity.get("edition_id") or "")
    is_home_edition = edition_id.lower() == "core" or bool(product_name and "home" in product_name.lower())
    binary_present = exe_path is not None
    ready = bool(is_windows and binary_present and not is_home_edition)
    provider_name = get_sandbox_provider_name(WINDOWS_SANDBOX_PROVIDER)

    if not is_windows:
        message = f"{provider_name} is only available on Windows hosts."
    elif is_home_edition:
        message = (
            f"{provider_name} is not supported on {product_name}. "
            "Use Windows Pro, Enterprise, or Education to enable it."
        )
    elif not binary_present:
        message = (
            f"{provider_name} executable was not found. "
            "Enable the Windows Sandbox feature and reboot the machine."
        )
    else:
        message = f"{provider_name} binaries were found and launch should be available."

    return {
        "provider": WINDOWS_SANDBOX_PROVIDER,
        "provider_name": provider_name,
        "ready": ready,
        "supported": bool(is_windows and not is_home_edition),
        "configured": True,
        "product_name": product_name,
        "raw_product_name": identity.get("product_name"),
        "edition_id": identity.get("edition_id"),
        "display_version": identity.get("display_version"),
        "build_number": identity.get("build_number"),
        "is_home_edition": is_home_edition,
        "executable_found": binary_present,
        "executable_path": exe_path,
        "executable_source": source,
        "message": message,
    }


def resolve_vboxmanage_exe() -> tuple[str | None, str | None]:
    env_override = os.environ.get("VBOXMANAGE_EXE")
    if env_override and os.path.exists(env_override):
        return env_override, "env"

    on_path = shutil.which("VBoxManage.exe") or shutil.which("VBoxManage")
    if on_path:
        return on_path, "path"

    for candidate in COMMON_VBOXMANAGE_PATHS:
        if candidate.exists():
            return str(candidate), "program_files"

    return None, None


def _run_vboxmanage(args: list[str], timeout_seconds: int = 15) -> tuple[int | None, str]:
    exe_path, _ = resolve_vboxmanage_exe()
    if not exe_path:
        return None, "VBoxManage.exe was not found."

    try:
        completed = subprocess.run(
            [exe_path] + args,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, "VBoxManage timed out while communicating with VirtualBox."
    except Exception as exc:
        return None, f"VBoxManage failed: {exc}"

    output = (completed.stdout or completed.stderr or "").strip()
    return completed.returncode, output


def get_virtualbox_vm_name() -> str:
    explicit = str(os.environ.get("VIRTUALBOX_VM_NAME") or "").strip()
    if explicit:
        return explicit

    machines = _read_virtualbox_registered_machines()
    if len(machines) == 1:
        return str(machines[0].get("name") or "").strip()
    return ""


def get_virtualbox_shared_folder_name() -> str:
    return str(os.environ.get("VIRTUALBOX_SHARED_FOLDER_NAME") or "CyberShieldSandbox").strip()


def get_virtualbox_guest_base_path() -> str:
    explicit = str(os.environ.get("VIRTUALBOX_GUEST_BASE_PATH") or "").strip()
    if explicit:
        return explicit
    return r"\\VBOXSVR\{0}".format(get_virtualbox_shared_folder_name())


def get_virtualbox_guest_session_path(session_id: str) -> str:
    return os.path.join(get_virtualbox_guest_base_path(), "sessions", session_id)


def _parse_machinereadable_output(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"')
    return values


def _read_virtualbox_registered_machines() -> list[dict[str, Any]]:
    if not VIRTUALBOX_GLOBAL_CONFIG.exists():
        return []

    try:
        tree = ET.parse(VIRTUALBOX_GLOBAL_CONFIG)
    except Exception:
        return []

    machines: list[dict[str, Any]] = []
    for entry in tree.findall(".//{*}MachineRegistry/{*}MachineEntry"):
        src = str(entry.attrib.get("src") or "").strip()
        if not src:
            continue
        metadata = _read_virtualbox_machine_file(Path(src))
        machine_name = metadata.get("name") or Path(src).stem
        machines.append(
            {
                "name": machine_name,
                "src": src,
                "shared_folders": metadata.get("shared_folders") or [],
            }
        )
    return machines


def _read_virtualbox_machine_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}

    try:
        tree = ET.parse(path)
    except Exception:
        return {}

    machine = tree.find(".//{*}Machine")
    if machine is None:
        return {}

    shared_folders: list[dict[str, Any]] = []
    for shared in machine.findall(".//{*}SharedFolders/{*}SharedFolder"):
        shared_folders.append(
            {
                "name": str(shared.attrib.get("name") or "").strip(),
                "host_path": str(shared.attrib.get("hostPath") or "").strip(),
                "auto_mount": str(shared.attrib.get("autoMount") or "").strip(),
            }
        )

    return {
        "name": str(machine.attrib.get("name") or "").strip(),
        "shared_folders": shared_folders,
    }


def _find_virtualbox_machine(vm_name: str) -> dict[str, Any] | None:
    normalized = str(vm_name or "").strip().lower()
    if not normalized:
        return None

    for machine in _read_virtualbox_registered_machines():
        if str(machine.get("name") or "").strip().lower() == normalized:
            return machine
    return None


def get_virtualbox_status() -> dict[str, Any]:
    provider_name = get_sandbox_provider_name(VIRTUALBOX_PROVIDER)
    exe_path, source = resolve_vboxmanage_exe()
    vm_name = get_virtualbox_vm_name()
    shared_folder_name = get_virtualbox_shared_folder_name()
    guest_base_path = get_virtualbox_guest_base_path()
    executable_found = exe_path is not None
    machine = _find_virtualbox_machine(vm_name)
    vm_exists = False
    vm_state: str | None = None
    query_error: str | None = None
    shared_folder_configured = False
    shared_folder_host_path: str | None = None

    if machine:
        vm_exists = True
        for shared_folder in machine.get("shared_folders") or []:
            if str(shared_folder.get("name") or "").strip() != shared_folder_name:
                continue
            shared_folder_configured = True
            shared_folder_host_path = str(shared_folder.get("host_path") or "").strip() or None
            break

    if executable_found and vm_name:
        return_code, output = _run_vboxmanage(["showvminfo", vm_name, "--machinereadable"])
        if return_code == 0:
            machine_info = _parse_machinereadable_output(output)
            vm_exists = True
            vm_state = machine_info.get("VMState")
        else:
            query_error = output or f"VBoxManage exited with code {return_code}."

    ready = bool(executable_found and vm_name and vm_exists and shared_folder_configured and not query_error)

    if not executable_found:
        message = (
            f"{provider_name} command line tools were not found. "
            "Install VirtualBox or set VBOXMANAGE_EXE."
        )
    elif not vm_name:
        message = (
            f"{provider_name} is installed, but no VM is configured yet. "
            "Set VIRTUALBOX_VM_NAME before launching the stack."
        )
    elif not vm_exists:
        detail = f" {query_error}" if query_error else ""
        message = (
            f"{provider_name} VM '{vm_name}' could not be queried. "
            "Confirm the VM name exactly matches VirtualBox and VBoxManage can access it."
            f"{detail}"
        ).strip()
    elif not shared_folder_configured:
        detail = f" VBoxManage status query also failed: {query_error}" if query_error else ""
        message = (
            f"{provider_name} VM '{vm_name}' exists, but shared folder '{shared_folder_name}' is not configured. "
            r"Add host path C:\Sandbox_VM_Input as a permanent shared folder in the VM settings."
            f"{detail}"
        ).strip()
    elif query_error:
        message = (
            f"{provider_name} VM '{vm_name}' is configured, but VBoxManage could not query it. "
            f"Fix VirtualBox CLI access before using it as the sandbox. {query_error}"
        )
    else:
        state_label = vm_state or "powered off"
        message = (
            f"{provider_name} VM '{vm_name}' is configured (state: {state_label}). "
            f"Review files through the shared folder path {guest_base_path}."
        )

    return {
        "provider": VIRTUALBOX_PROVIDER,
        "provider_name": provider_name,
        "ready": ready,
        "supported": executable_found,
        "configured": bool(vm_name),
        "executable_found": executable_found,
        "executable_path": exe_path,
        "executable_source": source,
        "vm_name": vm_name or None,
        "vm_exists": vm_exists,
        "vm_state": vm_state,
        "vm_source": machine.get("src") if machine else None,
        "shared_folder_name": shared_folder_name,
        "shared_folder_configured": shared_folder_configured,
        "shared_folder_host_path": shared_folder_host_path,
        "guest_base_path": guest_base_path,
        "query_error": query_error,
        "message": message,
    }


def get_sandbox_status() -> dict[str, Any]:
    provider = get_configured_sandbox_provider()
    if provider == VIRTUALBOX_PROVIDER:
        return get_virtualbox_status()
    return get_windows_sandbox_status()
