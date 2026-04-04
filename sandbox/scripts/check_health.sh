#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_DIR="$ROOT/pids"
LOG_DIR="$ROOT/logs"

check_service() {
  local name="$1"
  local pattern="$2"
  local pidfile="$PID_DIR/$name.pid"

  if [ -f "$pidfile" ]; then
    local pid
    pid=$(<"$pidfile")
    if kill -0 "$pid" 2>/dev/null; then
      echo "$name running (pid $pid)"
      return
    fi
  fi

  local live_pid
  live_pid=$(pgrep -f "$pattern" | head -n 1 || true)
  if [ -n "$live_pid" ]; then
    echo "$name running (pid $live_pid, recovered from process scan)"
  else
    echo "$name not started"
  fi
}

check_service backend 'python -m uvicorn app.main:app --host 127.0.0.1 --port 8000'
check_service sandbox 'sandbox_monitor.py'
check_service frontend 'node .*vite --host 127.0.0.1 --port 5173'

if [ -d "$LOG_DIR" ]; then
  echo "Logs are available in $LOG_DIR"
fi
