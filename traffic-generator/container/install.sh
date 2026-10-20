#!/bin/bash
# Guarded install of ap-trafficgen on AP-AUTOPILOT-01 (sudo bash install.sh BUILD_ID, from the unpacked release dir).
# Installs the image, the host control script and its directories. Starts NOTHING that sends traffic (the final check is a
# dry-run, which only validates the profile and prints the plan). Touches no existing container, image, compose project,
# BIG-IP, certificate or credential. Read-only preflight first; aborts before any change if anything differs.
set -euo pipefail
ID="${1:?BUILD_ID}"; REL="$(cd "$(dirname "$0")" && pwd)"; cd "$REL"
NAME=ap-trafficgen; TAG="ap-trafficgen:$ID"
BASE_TAG=aplab-py:0.1
BASE_ID=sha256:68cd67758515a2e371cde94b3512c60e57367f5fbfc8b06c87dac5d95844b316
LAB_CA=/opt/aplab/pki/ca.pem
ETC=/etc/ap-trafficgen; VAR=/var/lib/ap-trafficgen; BIN=/usr/local/sbin/ap-trafficgen
fail(){ echo "ABORT: $*" >&2; exit 2; }
[ "$(id -u)" = 0 ] || fail "run with sudo"

# ---- read-only preflight
[ "$(cat BUILD_ID)" = "$ID" ] || fail "BUILD_ID mismatch"
sha256sum --quiet -c SHA256SUMS || fail "release checksum mismatch"
[ "$(docker image inspect -f '{{.Id}}' "$BASE_TAG" 2>/dev/null)" = "$BASE_ID" ] || fail "base image $BASE_TAG is not $BASE_ID"
for p in $ETC $VAR $BIN; do [ ! -e $p ] || fail "$p already exists"; done
! docker inspect $NAME >/dev/null 2>&1 || fail "container $NAME already exists"
! docker image inspect "$TAG" >/dev/null 2>&1 || fail "image $TAG already exists"
[ -r $LAB_CA ] || fail "lab CA $LAB_CA missing"
! grep -q "PRIVATE KEY" $LAB_CA || fail "lab CA file contains a private key"
openssl x509 -in $LAB_CA -noout -subject >/dev/null || fail "lab CA is not a certificate"
[ "$(nproc)" -ge 2 ] && [ "$(df --output=avail -k /var/lib | tail -1)" -gt 2097152 ] || fail "host resources"

TS=$(date -u +%Y%m%dT%H%M%SZ); BK=/opt/aplab/backups/ap-trafficgen-install-$TS
install -d -m 700 "$BK"
docker ps -a --no-trunc --format '{{.Names}} {{.Image}} {{.ID}} {{.Status}}' | sed 's/ Up .*/ Up/' | sort > "$BK/containers.before"
docker image ls -q --no-trunc | sort > "$BK/images.before"
cp -p SHA256SUMS BUILD_ID CONTEXT.sha256 ap-trafficgen-context.tgz ap-trafficgen install.sh rollback.sh "$BK/"

# ---- build (no network, pinned base, no pull)
install -d -m 700 "$BK/context"; tar -xzf ap-trafficgen-context.tgz -C "$BK/context"
(cd "$BK/context" && sha256sum --quiet -c "$REL/CONTEXT.sha256") || fail "context mismatch"
docker build --network none --pull=false -q -f "$BK/context/container/Dockerfile" --build-arg BASE="$BASE_TAG@$BASE_ID" -t "$TAG" "$BK/context" > "$BK/image-id"
IMG=$(cat "$BK/image-id")
[ "$(docker image inspect -f '{{.Config.User}}' "$IMG")" = "65534:65534" ] || fail "image user"
docker run --rm --network none --entrypoint sha256sum "$IMG" /opt/trafficgen/simulator/f5_ai_workload_sim.py /opt/trafficgen/simulator/sim_profiles.py \
  /opt/trafficgen/simulator/sim_transport.py /opt/trafficgen/simulator/mcp_adapter.py /opt/trafficgen/simulator/profiles/project-a.json \
  /opt/trafficgen/trafficgen_entry.py | awk '{print $1}' > "$BK/image.sha256"
grep -E 'f5_ai_workload_sim|sim_profiles|sim_transport|mcp_adapter|project-a.json|trafficgen_entry' CONTEXT.sha256 | awk '{print $1}' | diff - "$BK/image.sha256" \
  || fail "image files differ from the release"

# ---- host files
install -d -m 755 $ETC
install -m 644 $LAB_CA $ETC/ca.pem
echo "$IMG" > $ETC/image; chmod 644 $ETC/image
echo 3600 > $ETC/max_duration_s; chmod 644 $ETC/max_duration_s
install -d -m 755 $VAR; install -d -m 750 -o 65534 -g 65534 $VAR/state; install -d -m 750 $VAR/runs
install -m 755 ap-trafficgen $BIN

# ---- verification (sends nothing)
docker ps -a --no-trunc --format '{{.Names}} {{.Image}} {{.ID}} {{.Status}}' | sed 's/ Up .*/ Up/' | sort > "$BK/containers.after"
diff "$BK/containers.before" "$BK/containers.after" || fail "existing containers changed (investigate; rollback.sh $ID)"
$BIN dry-run | tee "$BK/dry-run.log" | grep -q '"event":"dry-run ok"' || fail "dry-run failed (rollback.sh $ID)"
! docker inspect $NAME >/dev/null 2>&1 || fail "a generator container exists after install"
echo "installed ap-trafficgen $ID image=$IMG backup=$BK (nothing started)"
