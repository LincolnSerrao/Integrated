#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PID_DIR="$ROOT/sandbox/pids"

stop_by_pidfile() {
  local name="$1"
  local pidfile="$PID_DIR/$name.pid"

  if [ ! -f "$pidfile" ]; then
    return
  fi

  local pid
  pid=$(<"$pidfile")
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    echo "Stopped $name ($pid)"
  fi
  rm -f "$pidfile"
}

stop_by_pattern() {
  local name="$1"
  local pattern="$2"
  local pids

  pids=$(pgrep -f "$pattern" || true)
  if [ -n "$pids" ]; then
    echo "$pids" | xargs -r kill 2>/dev/null || true
    echo "Stopped $name by pattern"
  fi
}

stop_by_pidfile backend
stop_by_pidfile sandbox
stop_by_pidfile frontend

# More resilient pattern matching for Arch Linux process trees
stop_by_pattern backend 'uvicorn app.main:app'
stop_by_pattern sandbox 'python sandbox_monitor.py'
stop_by_pattern frontend 'vite'

echo "Cleanup complete."
