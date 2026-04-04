# Backend

The backend is a FastAPI service that accepts files, runs scanner logic, exposes sandbox and ML status, and serves the result/log APIs used by the frontend.

## What it does
- Accepts uploaded files from the Scan page
- Writes files into the configured staging directory
- Runs local scan logic immediately when possible
- Stores active scan results in memory
- Reads scan event logs for latest-result and logs pages
- Reports sandbox readiness and ML readiness to the UI

## Requirements
- Windows recommended
- Python 3.10+ for the basic API and scanner flow
- `fastapi`, `uvicorn`, `python-multipart`, `numpy`
- Optional ML environment for full model-based scanning

## Install
```powershell
cd Backend
pip install -r requirements.txt
```

Optional ML stack:
```powershell
cd Backend
pip install -r requirements-ml.txt
```

## Run
```powershell
cd Backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

## Main endpoints
- `GET /api/health`
- `GET /api/scan/ml-status`
- `GET /api/scan/sandbox-status`
- `GET /api/scan/config`
- `POST /api/scan/upload`
- `GET /api/scan/results/{file_name}`
- `GET /api/scan/logs`
- `GET /api/scan/latest`
- `GET /api/scan/files/{file_name}`
- `DELETE /api/scan/files/{file_name}`

## Environment
- `SANDBOX_STAGING_DIR`
  The staging folder the backend writes into before the sandbox monitor picks files up.
- `SANDBOX_PROVIDER`
  Sandbox backend selector, for example `virtualbox`.
- `VIRTUALBOX_VM_NAME`
  VirtualBox VM name when using the VirtualBox sandbox provider.

## ML notes
- The optional ML stack is easiest on Python 3.11 64-bit.
- If ML dependencies are missing, the scanner falls back to a reduced capability path and reports a warning in the scan result payload.
