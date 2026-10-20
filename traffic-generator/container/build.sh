#!/bin/bash
# Deterministic OFFLINE release builder for ap-trafficgen. Stages exactly the files the image needs into OUT/context,
# packs them reproducibly (fixed mtime/owner, gzip -n), writes SHA256SUMS and BUILD_ID. Builds no image, contacts nothing,
# deletes nothing, refuses a non-empty OUT.        Usage: bash container/build.sh OUT_DIR
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; OUT="${1:?out dir}"
sha(){ if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
[ ! -e "$OUT" ] || [ -z "$(ls -A "$OUT")" ] || { echo "ABORT: output exists and is not empty: $OUT"; exit 2; }
FILES="simulator/f5_ai_workload_sim.py simulator/sim_profiles.py simulator/sim_transport.py simulator/mcp_adapter.py
simulator/profiles/project-a.json container/trafficgen_entry.py container/Dockerfile"
mkdir -p "$OUT/context"; chmod 700 "$OUT"
for f in $FILES; do mkdir -p "$OUT/context/$(dirname "$f")"; cp "$ROOT/$f" "$OUT/context/$f"; chmod 644 "$OUT/context/$f"; touch -t 197001010000 "$OUT/context/$f"; done
COPYFILE_DISABLE=1 tar --format ustar --uid 0 --gid 0 -cf - -C "$OUT/context" $FILES | gzip -n > "$OUT/ap-trafficgen-context.tgz"
(cd "$OUT/context" && sha $FILES) > "$OUT/CONTEXT.sha256"
for f in ap-trafficgen install.sh rollback.sh; do cp "$ROOT/container/$f" "$OUT/$f"; chmod 700 "$OUT/$f"; done
ID=$(cat "$OUT/CONTEXT.sha256" "$OUT/ap-trafficgen" "$OUT/install.sh" "$OUT/rollback.sh" | sha | cut -c1-12)
printf '%s\n' "$ID" > "$OUT/BUILD_ID"
(cd "$OUT" && sha ap-trafficgen-context.tgz CONTEXT.sha256 ap-trafficgen install.sh rollback.sh BUILD_ID > SHA256SUMS)
echo "built ap-trafficgen release $ID in $OUT (no image built)"
