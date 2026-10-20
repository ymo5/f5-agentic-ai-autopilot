#!/usr/bin/env bash
# Offline SIMULATED demo: runs the real Autopilot web application on 127.0.0.1 against mock BIG-IP / host executors,
# recorded discovery fixtures and a temporary database. No network access to any lab; no real device is changed.
#   scripts/run-demo.sh [port] [scenario]     scenarios: empty | discovered | failed-then-deployed (default) | compare | placement-evidence
# Requires Python 3.12. Creates .venv-demo/ in the repository on first run.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3.12}"
command -v "$PY" >/dev/null || { echo "Python 3.12 is required (set PYTHON=/path/to/python3.12)" >&2; exit 2; }
if [ ! -x .venv-demo/bin/python ]; then
  "$PY" -m venv .venv-demo
  .venv-demo/bin/pip install -q -r requirements-dev.txt   # the demo reuses the test fixtures (needs pytest)
fi
echo "SIMULATED DEMO — all BIG-IP, host and agent responses are mocks/fixtures. Do not expose this server."
exec .venv-demo/bin/python devtools/devserver.py "${1:-8765}" "${2:-failed-then-deployed}"
