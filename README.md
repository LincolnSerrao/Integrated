# Cyber Shield Innovators

Cyber Shield Innovators is a Windows-first malware triage project with three main parts:
- a React frontend for uploads, status, results, and logs
- a FastAPI backend for file intake, scan orchestration, and status APIs
- a host-side sandbox monitor that watches a staging folder and hands files into an isolated sandbox session

The current preferred sandbox backend is `VirtualBox` with a Windows guest VM. The project itself stays on the host machine. Only the suspicious file review step happens inside the VM through a shared folder.

## What the project does
- Monitors a staging/download folder for completed files
- Scans files with the backend and optional ML pipeline
- Moves queued files into an isolated sandbox review session
- Lets the user approve or reject files from inside the sandbox guest
- Restores approved files to Downloads or drops rejected files
- Exposes a frontend dashboard, scan page, result page, and logs page

## Project structure
- [Frontend](./Frontend) - React + Vite UI
- [Backend](./Backend) - FastAPI API and scanner logic
- [sandbox](./sandbox) - sandbox monitor, launcher scripts, and sandbox docs

## Requirements

### Host requirements
- Windows 10 or Windows 11
- PowerShell
- Python 3.10+ for the basic backend and sandbox monitor
- `py -3.14` available if you want to use the current launcher scripts as-is
- Node.js 18+ and `npm`
- VirtualBox 7.x installed on the host

### VirtualBox requirements
- A Windows guest VM
- Guest Additions installed in the guest
- A permanent shared folder named `CyberShieldSandbox`
- That shared folder mapped to host path `C:\Sandbox_VM_Input`

### Optional ML requirements
- Separate Python environment recommended
- Python 3.11 (64-bit) is the most practical option for the optional ML stack
- See [Backend/requirements-ml.txt](./Backend/requirements-ml.txt)

## Install

### Backend
```powershell
cd Backend
pip install -r requirements.txt
```

### Frontend
```powershell
cd Frontend
npm install
```

### Sandbox monitor
```powershell
cd sandbox
pip install -r requirements.txt
```

## Run the project
From the sandbox folder:

```powershell
cd sandbox
$env:SANDBOX_PROVIDER = "virtualbox"
$env:VIRTUALBOX_VM_NAME = "Win11-Analysis-01"
$env:VIRTUALBOX_GUEST_BASE_PATH = "\\VBOXSVR\CyberShieldSandbox"
powershell -ExecutionPolicy Bypass -File .\scripts\Start-BackendAndSandbox.ps1
```

This starts:
- the backend
- the sandbox monitor
- the frontend
- the VirtualBox VM window automatically when VirtualBox mode is active

Frontend:
- `http://localhost:5173`

Backend:
- `http://127.0.0.1:8000`

Stop everything:

```powershell
cd sandbox
powershell -ExecutionPolicy Bypass -File .\scripts\Stop-BackendAndSandbox.ps1
```

## How sandbox review works
1. The host app receives or detects a file in the staging folder.
2. The sandbox monitor creates a session under `C:\Sandbox_VM_Input\sessions\...`.
3. The VirtualBox guest opens separately from the host project.
4. Inside the guest, open `\\VBOXSVR\CyberShieldSandbox\sessions\...`.
5. Approve a file by moving it from `in` to `out`.
6. Reject a file by deleting it from `in`.

The project code does not need to be moved into the VM.

## Notes
- The combined launcher uses the project-local staging path `sandbox\staging\Download`.
- If you run the monitor by itself, it can still use its standalone default staging path behavior.
- Set `VIRTUALBOX_OPEN_ON_START=false` if you want the launcher to stop auto-opening the VM window.

## More docs
- [Backend README](./Backend/README.md)
- [Sandbox README](./sandbox/README.md)
