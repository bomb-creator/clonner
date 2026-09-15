#!/usr/bin/env bash
# One-command launcher: creates a venv if needed, installs deps, starts the server.
set -euo pipefail

cd "$(dirname "$0")"

PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"
VENV=".venv"
PY="${PYTHON:-python3}"

if [ ! -d "$VENV" ]; then
  echo "==> Creating virtual environment in $VENV"
  "$PY" -m venv "$VENV"
fi

# shellcheck disable=SC1091
source "$VENV/bin/activate"

if ! python -c "import fastapi, uvicorn, httpx, pydantic" 2>/dev/null; then
  echo "==> Installing dependencies"
  pip install --quiet --upgrade pip
  pip install --quiet -r requirements.txt
fi

if [ -f .env ]; then
  echo "==> Loading .env"
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

echo "==> Starting Code Review Agent on http://${HOST}:${PORT}"
echo "    (open http://localhost:${PORT} in your browser)"
exec python -m uvicorn backend.main:app --host "$HOST" --port "$PORT" "$@"
