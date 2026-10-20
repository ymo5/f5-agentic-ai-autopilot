#!/usr/bin/env bash
# Read-only health check of a running installation. Usage: scripts/healthcheck.sh [base-url]
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
[ -f deploy/autopilot/.env ] && { set -a; . deploy/autopilot/.env; set +a; }
URL="${1:-http://${AUTOPILOT_BIND_HOST:-127.0.0.1}:${AUTOPILOT_BIND_PORT:-8000}}"
rc=0
check(){ local name="$1" url="$2"; if out=$(curl -fsS --max-time 5 "$url" 2>&1); then echo "OK    $name  $out" | cut -c1-160; else echo "FAIL  $name  $url"; rc=1; fi; }
check "web /healthz" "$URL/healthz"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$URL/api/me"); [ "$code" = 401 ] && echo "OK    auth enforced (/api/me -> 401 without a session)" || { echo "FAIL  /api/me returned $code (expected 401)"; rc=1; }
if command -v docker >/dev/null && [ -f deploy/autopilot/docker-compose.yml ]; then
  (cd deploy/autopilot && docker compose ps --format 'table {{.Service}}\t{{.Status}}' 2>/dev/null) || true
  (cd deploy/autopilot && docker compose exec -T autopilot-deployer python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8100/healthz',timeout=5).read().decode())" 2>/dev/null \
     && echo "OK    deployer /healthz") || echo "INFO  deployer not running (web-only installation or credentials not configured)"
fi
exit $rc
