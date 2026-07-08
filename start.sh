#!/bin/bash
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

PROFILE="${1:-default}"

echo "=== AURORA C2 Teamserver ==="
echo "  Profile: ${PROFILE}"
echo ""

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 not found."
  exit 1
fi

if [ ! -d "teamserver/venv" ]; then
  echo "Creating Python venv..."
  python3 -m venv teamserver/venv
fi

echo "Installing dependencies..."
teamserver/venv/bin/pip install -q --disable-pip-version-check -r teamserver/requirements.txt

echo "Starting teamserver with profile '${PROFILE}'..."
exec teamserver/venv/bin/python teamserver/server.py -profile "$PROFILE"
