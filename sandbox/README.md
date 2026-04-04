# Sandbox Monitor

The sandbox monitor is the host-side process that watches the staging folder, creates review sessions, launches the configured sandbox backend, and waits for the user decision.

## What it does
- Watches the configured staging/download folder
- Ignores incomplete temporary download files
- Waits for file size stability before processing
- Creates isolated review sessions under `C:\Sandbox_VM_Input\sessions`
- Scans files locally before and during sandbox handoff when possible
- Launches the configured sandbox backend
- Restores approved files to the host Downloads folder
- Keeps logs in `C:\Sandbox_Logs\sandbox.log`

## Requirements
- Windows 10 or Windows 11
- Python 3.10+
- `watchdog`, `pystray`, `Pillow`

Supported sandbox backends:
- `VirtualBox` with a Windows guest VM and Guest Additions
- `Windows Sandbox` on supported host editions

## Install
```powershell
cd sandbox
pip install -r requirements.txt
```

## Run the full stack
```powershell
cd sandbox
$env:SANDBOX_PROVIDER = "virtualbox"
$env:VIRTUALBOX_VM_NAME = "Win11-Analysis-01"
$env:VIRTUALBOX_GUEST_BASE_PATH = "\\VBOXSVR\CyberShieldSandbox"
powershell -ExecutionPolicy Bypass -File .\scripts\Start-BackendAndSandbox.ps1
```

This starts:
- the backend window
- the sandbox monitor window
- the frontend dev server
- the VirtualBox VM window when VirtualBox mode is enabled

Stop:

```powershell
cd sandbox
powershell -ExecutionPolicy Bypass -File .\scripts\Stop-BackendAndSandbox.ps1
```

Health check:

```powershell
cd sandbox
powershell -ExecutionPolicy Bypass -File .\scripts\Check-StackHealth.ps1
```

Run only the monitor:

```powershell
cd sandbox
python sandbox_monitor.py
```

## VirtualBox setup
- Create or use a Windows guest VM
- Install Guest Additions
- Add a permanent shared folder named `CyberShieldSandbox`
- Set that shared folder to host path `C:\Sandbox_VM_Input`
- Make sure the guest can open `\\VBOXSVR\CyberShieldSandbox`

Optional environment variables:
- `SANDBOX_PROVIDER=virtualbox`
- `VIRTUALBOX_VM_NAME=<your vm name>`
- `VIRTUALBOX_GUEST_BASE_PATH=\\VBOXSVR\CyberShieldSandbox`
- `VIRTUALBOX_OPEN_ON_START=false` to disable automatic VM opening on project start

## Review flow inside the VM
Open:

```text
\\VBOXSVR\CyberShieldSandbox\sessions\
```

Then for the newest session:
- review the file inside `in`
- approve by moving it to `out`
- reject by deleting it from `in`

## Logs
Log file:
- `C:\Sandbox_Logs\sandbox.log`

Common actions:
- `FILE_DETECTED`
- `FILE_MOVED_TO_SANDBOX`
- `SANDBOX_STARTED`
- `USER_ALLOWED`
- `USER_REJECTED`
- `SANDBOX_STOPPED`
