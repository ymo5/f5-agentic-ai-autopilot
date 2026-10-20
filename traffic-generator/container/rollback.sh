#!/bin/bash
# Rollback of ap-trafficgen on AP-AUTOPILOT-01 (sudo bash rollback.sh BUILD_ID). Stops a running generator (stop file, then
# docker stop), archives its log/status, moves every installed host file into a backup directory (nothing is deleted
# except the ap-trafficgen image tag, which install.sh can rebuild from the release) and verifies that no other container
# changed. Touches no other container, image, compose project, BIG-IP, certificate or credential.
set -euo pipefail
ID="${1:?BUILD_ID}"; NAME=ap-trafficgen; TAG="ap-trafficgen:$ID"
ETC=/etc/ap-trafficgen; VAR=/var/lib/ap-trafficgen; BIN=/usr/local/sbin/ap-trafficgen
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 2; }
TS=$(date -u +%Y%m%dT%H%M%SZ); BK=/opt/aplab/backups/ap-trafficgen-rollback-$TS
install -d -m 700 "$BK"
docker ps -a --no-trunc --format '{{.Names}} {{.Image}} {{.ID}} {{.Status}}' | grep -v "^$NAME " | sed 's/ Up .*/ Up/' | sort > "$BK/containers.before"
if docker inspect $NAME >/dev/null 2>&1; then
  if [ -x $BIN ]; then $BIN stop || true; $BIN archive || true; fi
  if docker inspect $NAME >/dev/null 2>&1; then docker stop -t 30 $NAME >/dev/null || true; docker logs $NAME > "$BK/run.log" 2>&1 || true; docker rm $NAME >/dev/null; fi
fi
for p in $BIN $ETC $VAR; do [ ! -e $p ] || mv $p "$BK/"; done
IMG_USERS=$(docker ps -a -q --filter ancestor="$TAG" | wc -l)
[ "$IMG_USERS" = 0 ] || { echo "ABORT: containers still use $TAG" >&2; exit 2; }
if docker image inspect "$TAG" >/dev/null 2>&1; then docker image inspect -f '{{.Id}}' "$TAG" > "$BK/image-id"; docker rmi "$TAG" >/dev/null; fi
docker ps -a --no-trunc --format '{{.Names}} {{.Image}} {{.ID}} {{.Status}}' | grep -v "^$NAME " | sed 's/ Up .*/ Up/' | sort > "$BK/containers.after"
diff "$BK/containers.before" "$BK/containers.after" || { echo "WARNING: other containers changed during rollback" >&2; exit 3; }
echo "rolled back ap-trafficgen $ID; host files and run archives moved to $BK"
