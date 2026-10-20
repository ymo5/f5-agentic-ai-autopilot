#!/usr/bin/env bash
# Install / start the Autopilot web + deployer containers on ONE Linux Docker host (run as root from the repository root).
# What it does (idempotent, never overwrites existing config or secrets):
#   1. checks Docker + compose; 2. creates data/secrets directories with the expected ownership;
#   3. creates deploy/autopilot/.env and autopilot.yaml from the examples if absent; 4. generates web/deployer secrets;
#   5. builds the image and starts the web container (and the deployer only if its credential files exist).
# It does NOT create accounts (run scripts/bootstrap-admin.sh next), contact a BIG-IP, or open a live window.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"; D="$ROOT/deploy/autopilot"
[ "$(id -u)" = 0 ] || { echo "run as root (it creates /var/lib/autopilot and /opt/aplab/secrets)" >&2; exit 2; }
command -v docker >/dev/null && docker compose version >/dev/null || { echo "Docker Engine with the compose plugin is required" >&2; exit 2; }
[ -f "$D/.env" ] || { cp "$D/.env.example" "$D/.env"; echo "created $D/.env from the example — review it"; }
set -a; . "$D/.env"; set +a
CFGF="$D/${AUTOPILOT_CONFIG_FILE:-./autopilot.local.yaml}"; CFGF="${CFGF/\/.\//\/}"
[ -f "$CFGF" ] || { cp "$D/autopilot.example.yaml" "$CFGF"; echo "created $CFGF from autopilot.example.yaml — edit it for YOUR lab before discovery"; }
DATA="${AUTOPILOT_DATA:-/var/lib/autopilot}"; SEC="${APLAB_SECRETS:-/opt/aplab/secrets}"; PKI="${APLAB_PKI:-/opt/aplab/pki}"
getent group 10010 >/dev/null || groupadd -g 10010 apdb
install -d -m 2770 -o 10001 -g 10010 "$DATA"
install -d -m 0755 "$PKI"
install -d -m 0750 -g 10010 "$SEC"
[ -f "$SEC/autopilot.env" ] || APLAB_SECRETS="$SEC" "$ROOT/scripts/gen-secrets.sh" "$SEC"
chgrp 10010 "$SEC/autopilot.env" "$SEC/deployer" "$SEC/deployer/deployer_token" 2>/dev/null || true
chmod 640 "$SEC/autopilot.env"; chmod 750 "$SEC/deployer"; chmod 640 "$SEC/deployer/deployer_token"
cd "$D"
docker compose build
NEED="bigip_cert_sha256 bigip_deployer.json bigip_observer.json apdeploy_ed25519 known_hosts"
missing=""; for f in $NEED; do [ -f "$SEC/deployer/$f" ] || missing="$missing $f"; done
if [ -n "$missing" ]; then
  echo "deployer credential files missing:$missing — starting the web UI only (deployment features unavailable)."
  echo "See docs/CONFIGURATION.md#deployer-credential-files to enable the deployer."
  docker compose up -d --no-deps autopilot
else
  docker compose up -d
fi
echo "next: scripts/bootstrap-admin.sh   then: scripts/healthcheck.sh"
