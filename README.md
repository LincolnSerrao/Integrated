# Cyber Shield Innovators

Cyber Shield Innovators is a malware triage project with three main parts:
- a React frontend for status, review results, and logs
- a FastAPI backend for scan orchestration, quarantine APIs, and ML status
- a host-side sandbox monitor that captures downloads into quarantine before release

The current Linux flow is quarantine-first and always on while the software is running.
Downloads are redirected into a controlled capture inbox, moved into quarantine, analyzed, and only released after user review.

## What the project does
- Redirects Linux downloads into a controlled capture inbox
- Watches mounted external drives while the software is running
- Moves detected files into quarantine before the user receives them
- Scans files with the backend and optional ML pipeline
- Lets the user release safe files to a chosen location
- Lets the user override and release unsafe files only after an explicit warning
- Deletes quarantined copies after release or rejection while keeping scan history in logs
- Exposes a frontend dashboard, scan page, result page, and logs page

## Project structure
- [Frontend](./Frontend) - React + Vite UI
- [Backend](./Backend) - FastAPI API and scanner logic
- [sandbox](./sandbox) - sandbox monitor and related docs

## Current Linux behavior
- Capture is always on whenever the backend and sandbox monitor are running
- Linux downloads are redirected to `capture/DownloadInbox`
- Quarantined files are stored under `staging/Download`
- Safe files are released only after the user chooses where to save them
- Unsafe files stay in quarantine unless the user explicitly overrides the warning
- Analysis history remains available in backend logs even after the quarantined file is deleted

Important note:
This does not mean the app can inspect every possible filesystem event on Linux. The current always-on coverage is:
- system downloads that honor the Linux download directory
- mounted external drives watched by the monitor

Apps that were already open before the software started may need to be restarted so they pick up the redirected download directory.

## Requirements

### Linux host requirements
- Arch Linux or another modern Linux distribution
- Python 3.10+
- Node.js 18+ and `npm`
- KDE if you want native folder pickers through `kdialog`

### Optional ML requirements
- Python 3.11 is the most practical option for the optional ML stack
- See [Backend/requirements-ml.txt](./Backend/requirements-ml.txt)

## Install

### Backend
```bash
cd Backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Frontend
```bash
cd Frontend
npm install
```

### Sandbox monitor
```bash
cd sandbox
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r ../Backend/requirements.txt
```

## Run the project
Open three terminals from the project root.

### Terminal 1: backend
```bash
cd /home/lincoln/Desktop/integrated/Backend
source .venv-ml/bin/activate
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Terminal 2: frontend
```bash
cd /home/lincoln/Desktop/integrated/Frontend
/home/lincoln/.cache/ms-playwright-go/1.50.1/node node_modules/vite/bin/vite.js --host 127.0.0.1 --port 5173
```

If `node` and `npm` are installed normally on your system, you can use:
```bash
cd /home/lincoln/Desktop/integrated/Frontend
npm run dev -- --host 127.0.0.1 --port 5173
```

### Terminal 3: sandbox monitor
```bash
cd /home/lincoln/Desktop/integrated/sandbox
source /home/lincoln/Desktop/integrated/Backend/.venv-ml/bin/activate
python sandbox_monitor.py
```

Frontend:
- `http://127.0.0.1:5173`

Backend:
- `http://127.0.0.1:8000`

## Review flow
1. A download lands in the Linux capture inbox first.
2. The sandbox monitor detects the file and waits for it to become stable.
3. The file is moved into quarantine under `staging/Download`.
4. The backend scans it and logs the result.
5. If the file is safe, the UI prompts the user to choose where to save it.
6. If the file is unsafe, the UI warns the user and allows explicit override.
7. After release or rejection, the quarantined file is removed but the analysis history remains in logs.

## Notes
- The current UI treats capture as always on, not as a user-toggle feature.
- The backend rewrites the Linux download directory to the capture inbox on startup.
- Mounted external drives are still watched automatically.
- Runtime quarantine and capture contents are intentionally ignored by Git.

## More docs
- [Backend README](./Backend/README.md)
- [Sandbox README](./sandbox/README.md)
