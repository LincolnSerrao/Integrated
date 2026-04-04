#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PID_DIR="$ROOT/sandbox/pids"
LOG_DIR="$ROOT/sandbox/logs"
mkdir -p "$PID_DIR" "$LOG_DIR"

echo "Starting Integrated Project Stack..."

# 1. Start Backend
echo "Launching Backend (FastAPI)..."
cd "$ROOT/Backend"
source .venv-ml/bin/activate
nohup uvicorn app.main:app --reload --host 127.0.0.1 --port 8000 > "$LOG_DIR/backend.log" 2>&1 &
echo $! > "$PID_DIR/backend.pid"

# Wait for backend health
echo "Waiting for Backend to initialize..."
for i in {1..10}; do
  if curl -s http://127.0.0.1:8000/api/health | grep -q "ok"; then
    break
  fi
  sleep 1
done

# 2. Start Frontend
echo "Launching Frontend (Vite)..."
cd "$ROOT/Frontend"
nohup npm run dev -- --host 127.0.0.1 --port 5173 > "$LOG_DIR/frontend.log" 2>&1 &
echo $! > "$PID_DIR/frontend.pid"

# 3. Start Sandbox Monitor
echo "Launching Sandbox Monitor..."
cd "$ROOT/sandbox"
nohup python sandbox_monitor.py > "$LOG_DIR/monitor_stdout.log" 2>&1 &
echo $! > "$PID_DIR/sandbox.pid"

echo "------------------------------------------------"
echo "Project is starting up!"
echo "Frontend: http://127.0.0.1:5173"
echo "Backend API: http://127.0.0.1:8000"
echo "Logs are located in: $ROOT/sandbox/logs/"
echo "------------------------------------------------"
echo "To stop the project, run: bash sandbox/scripts/stop.sh"