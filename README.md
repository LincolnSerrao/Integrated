# Integrated

This repository combines three parts of the project:
- `Backend/` - FastAPI backend and ML scanning logic
- `Frontend/` - React UI for uploads, results, and scan logs
- `sandbox/` - download monitor and local sandbox review flow

## Architecture

- The frontend sends uploads to the backend.
- The backend scans files with the trained PE model, heuristic fallback logic, and image steganography checks.
- The sandbox monitor watches configured locations, stages files for review, logs scan events, and returns or blocks files based on the workflow.

## Linux Defaults

The Linux flow uses these defaults unless overridden with environment variables:
- staging: `/tmp/cybershield/staging`
- sandbox session root: `/tmp/cybershield/sandbox`
- logs: `/tmp/cybershield/logs`
- downloads: `~/Downloads`

## Start The Stack

```bash
bash sandbox/scripts/start.sh
```

## Stop The Stack

```bash
bash sandbox/scripts/stop.sh
```

## Check Health

```bash
bash sandbox/scripts/check_health.sh
```

## Backend Setup

```bash
cd Backend
python -m venv .venv-ml
source .venv-ml/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-ml.txt
```

Run the API manually:

```bash
cd Backend
source .venv-ml/bin/activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Backend Endpoints

- `GET /api/health`
- `GET /api/scan/ml-status`
- `GET /api/scan/config`
- `POST /api/scan/upload`
- `GET /api/scan/results/{file_name}`
- `GET /api/scan/logs`
- `GET /api/scan/latest`
- `GET /api/scan/files/{file_name}`
- `DELETE /api/scan/files/{file_name}`

### ML Setup

Recommended:
- use a dedicated virtual environment
- use Python 3.11+

One-command setup:

```bash
cd Backend
bash scripts/setup_ml_linux.sh
```

Verify ML readiness:

```bash
curl -s http://127.0.0.1:8000/api/scan/ml-status
```

`ready: true` means the model files and ML libraries are available.

### Backend Notes

- Upload scans run through the backend and produce a stored result payload.
- If ML dependencies are unavailable, the scanner falls back to the heuristic engine and returns a warning.
- The backend staging directory can be overridden with `SANDBOX_STAGING_DIR`.

## Frontend Setup

```bash
cd Frontend
npm install
npm run dev
```

Optional frontend env in `Frontend/.env`:

```env
VITE_BACKEND_URL=http://127.0.0.1:8000
```

## Sandbox Monitor Setup

Install dependencies:

```bash
cd sandbox
python -m pip install -r sandbox-requirements.txt
```

Run only the monitor:

```bash
cd sandbox
python sandbox_monitor.py
```

### Sandbox Notes

- The monitor watches staged downloads, waits for files to finish writing, scans them, and opens them for review.
- If `firejail` is installed, sandboxed review launches through it.
- If `firejail` is unavailable, the monitor falls back to `xdg-open`.
- Legacy Windows PowerShell scripts remain under `sandbox/scripts/` for reference.

### Optional Environment Overrides

```bash
export SANDBOX_STAGING_DIR=/home/youruser/cybershield/staging
export SANDBOX_DIR=/home/youruser/cybershield/sandbox
export SANDBOX_LOG_DIR=/home/youruser/cybershield/logs
export DOWNLOADS_DIR=/home/youruser/Downloads
```

## Tests

Run the backend smoke tests with:

```bash
cd Backend
python -m unittest discover -s tests
```

## Troubleshooting

- If the frontend cannot reach the backend, confirm the API is running on `127.0.0.1:8000`.
- If automatic review does not open in a sandbox, check whether `firejail` is installed.
- If the monitor still falls back to heuristic mode, confirm ML dependencies and model files are present.
