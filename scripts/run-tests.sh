#!/usr/bin/env bash
# Offline test suites (no lab access): Autopilot (pytest), Traffic Generator (pytest), optional browser suite (Chrome + Node).
#   scripts/run-tests.sh [--browser]
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3.12}"
if [ ! -x .venv-dev/bin/python ]; then "$PY" -m venv .venv-dev && .venv-dev/bin/pip install -q -r requirements-dev.txt; fi
export PYTHONDONTWRITEBYTECODE=1
echo "== Autopilot (app/tests)"; (cd app && ../.venv-dev/bin/python -B -m pytest -q -p no:cacheprovider tests)
echo "== Traffic Generator (offline)"; (cd traffic-generator/simulator && ../../.venv-dev/bin/python -B -m pytest -q -p no:cacheprovider tests_offline)
if [ "${1:-}" = "--browser" ]; then
  echo "== Browser regression suite (headless Chrome against the simulated demo)"
  AP_PYTHON="$PWD/.venv-dev/bin/python" node devtools/browser/run.mjs
fi
