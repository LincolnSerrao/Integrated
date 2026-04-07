# Cyber Shield Innovators

Cyber Shield Innovators is a Linux-first malware triage project with a React frontend, a FastAPI backend, and a host-side monitor that captures files before release. The current implementation is built around an always-on quarantine workflow: files are redirected into a controlled capture inbox, moved into review storage, analyzed, and only released after the user explicitly decides what to do.

## What The Project Does

- Redirects Linux downloads into a capture inbox while the stack is running
- Watches mounted external drives and configured folders for incoming files
- Moves qualifying files into quarantine before normal use
- Scores files with a heuristic path and an optional ML model path
- Logs every analysis event to a JSONL scan history
- Lets the user release safe files, override warnings, delete files, or open them in an isolated project sandbox
- Exposes dashboard, manual scan, results, logs, and sandbox console screens in the frontend

## Architecture

### Frontend

The UI lives in `Frontend/` and is a React 18 + Vite app. It polls the backend for:

- sandbox readiness
- ML/model readiness
- capture configuration
- latest actionable scan result
- sandbox session history

Main pages:

- `Dashboard`: shows capture status, review storage, release folder, mounted volumes, and runtime readiness
- `Scan Page`: manually uploads a file for analysis without changing live capture settings
- `Result Page`: shows the active review item and allows save, release, delete, or isolated sandbox launch
- `Logs Page`: shows current-session scan history with risk scores, warnings, evidence, and model metadata
- `Sandbox Console`: shows stored disposable sandbox sessions, file trees, restrictions, and analysis details

### Backend

The backend lives in `Backend/` and is a FastAPI service that:

- forces Linux capture configuration on startup
- stores quarantine/review files under the configured staging directory
- scans uploaded or captured files
- exposes status, config, results, logs, restore, delete, and sandbox-session APIs
- records scan events in `Backend/app/reports/scan_events.jsonl`

Important behavior in the current code:

- On Linux startup, the backend rewrites `XDG_DOWNLOAD_DIR` to the capture inbox
- The backend keeps capture always on while the software is running
- Safe files are not auto-restored to Downloads; they are released only after the user chooses a destination
- Unsafe files stay in quarantine unless the user explicitly overrides the warning

### Sandbox Monitor

The monitor lives in `sandbox/sandbox_monitor.py` and continuously polls the configured watch directories. It:

- skips temporary or incomplete downloads
- waits for file size stability
- captures executable files and common image files
- moves them into quarantine
- triggers project-sandbox analysis
- writes review-required events back into the scan log

## Current Workflow

### Live capture flow

1. A file lands in the Linux capture inbox or another watched location.
2. The sandbox monitor detects the file and waits for it to become stable.
3. The file is moved into quarantine under `staging/Download` by default.
4. The backend analyzes the file and writes an event to the scan log.
5. The frontend opens the result/review flow for the latest actionable item.
6. The user can:
   - choose a save folder for a safe file
   - explicitly release a suspicious or malicious file anyway
   - delete the quarantined copy
   - open the file inside the project sandbox runtime

### Manual scan flow

1. The user selects a file from the `Scan Page`.
2. The file is copied into quarantine/review storage.
3. The backend analyzes it immediately.
4. The file can then be saved or deleted from the `Result Page`.

## Project Structure

- `Frontend/`: React + Vite operator UI
- `Backend/`: FastAPI API, scan logic, watch configuration, sandbox status, and model artifacts
- `sandbox/`: host-side monitor and legacy sandbox docs/scripts
- `capture/`: runtime-created capture inbox, ignored by Git
- `staging/`: runtime-created quarantine/review storage, ignored by Git

## Requirements

### Recommended host platform

The active project flow is clearly Linux-first.

- Linux host
- Python 3.10+ for the base backend and monitor
- Node.js 18+ and `npm` for the frontend
- `firejail` if you want the native Linux isolated launch flow to be fully available
- KDE is helpful if you want the backend's native folder picker endpoints through `kdialog`

### Optional ML stack

The repository includes model artifacts and an optional ML dependency set in `Backend/requirements-ml.txt`.

- Recommended Python: 3.11
- ML path depends on `torch`, `lief`, `scikit-learn`, and EMBER feature extraction
- If the ML stack is unavailable, the scanner falls back to heuristic or reduced-capability review behavior

### Legacy Windows material

There are still Windows-oriented docs and helper scripts under `sandbox/` and `sandbox/backend/`, but the root project code now defaults to the Linux project-sandbox provider when run on Linux.

## Quick Start

```bash
git clone https://github.com/LincolnSerrao/Integrated.git
cd Integrated
```

Then install the backend, frontend, and monitor dependencies shown below.

## Installation

### 1. Backend

```bash
cd Backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If you want the optional ML stack, use a separate Python 3.11 environment or extend the backend environment:

```bash
cd Backend
source .venv/bin/activate
pip install -r requirements-ml.txt
```

### 2. Frontend

```bash
cd Frontend
npm install
```

### 3. Sandbox monitor

The monitor imports backend modules, so it needs both its own dependencies and the backend dependencies available in the active Python environment.

```bash
cd sandbox
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r ../Backend/requirements.txt
```

Using the same Python environment for the backend and the monitor is the simplest option.

## Running The Stack

Open three terminals from the project root.

### Terminal 1: backend

```bash
cd Backend
source .venv/bin/activate
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

If you created a separate ML-enabled environment, activate that one instead.

### Terminal 2: frontend

```bash
cd Frontend
npm run dev -- --host 127.0.0.1 --port 5173
```

### Terminal 3: sandbox monitor

```bash
cd sandbox
source .venv/bin/activate
python sandbox_monitor.py
```

Endpoints:

- Frontend: `http://127.0.0.1:5173`
- Backend: `http://127.0.0.1:8000`

## Important Runtime Behavior

- Capture is always on while the backend and monitor are running
- Linux downloads are redirected into `capture/DownloadInbox`
- Default quarantine/review storage is `staging/Download`
- Default release directory on Linux is `~/CyberShield-Released`
- Mounted external drives discovered from `/proc/mounts` are watched automatically when enabled
- Existing browser or transfer app sessions may need to be restarted after the backend starts so they pick up the new download directory
- Runtime-created `capture/` and `staging/` folders are intentionally ignored by Git

## Main Backend Endpoints

- `GET /api/health`
- `GET /api/scan/ml-status`
- `GET /api/scan/sandbox-status`
- `GET /api/scan/config`
- `GET /api/scan/watch-targets`
- `PUT /api/scan/watch-targets`
- `POST /api/scan/pick-directory`
- `POST /api/scan/pick-release-directory`
- `POST /api/scan/strict-capture/apply`
- `POST /api/scan/upload`
- `GET /api/scan/results/{file_name}`
- `GET /api/scan/logs`
- `GET /api/scan/latest`
- `GET /api/scan/files/{file_name}`
- `POST /api/scan/files/{file_name}/launch-native-sandbox`
- `POST /api/scan/files/{file_name}/restore`
- `DELETE /api/scan/files/{file_name}`
- `GET /api/sandbox/sessions`
- `GET /api/sandbox/sessions/latest`
- `GET /api/sandbox/sessions/{session_id}`

## Detection Notes

- Non-PE files use the heuristic scan path
- PE files attempt the ML path when the ML stack is available
- Default thresholds in code:
  - allow below `0.20`
  - block above `0.80`
  - otherwise hold for review
- Scan history stores model identity, artifact names, thresholds, warnings, session ids, and action history

## Useful Paths

- Backend scan log: `Backend/app/reports/scan_events.jsonl`
- Backend watch config: `Backend/app/config/watch_targets.json`
- Sandbox monitor log: `sandbox/logs/sandbox.log`
- Model artifact: `Backend/app/models/cyber_shield_zero_day.pth`
- Normalization artifact: `Backend/app/models/normalization.npz`

## Related Docs

- [Backend README](./Backend/README.md)
- [Sandbox README](./sandbox/README.md)
- [Legacy sandbox backend README](./sandbox/backend/README.md)
