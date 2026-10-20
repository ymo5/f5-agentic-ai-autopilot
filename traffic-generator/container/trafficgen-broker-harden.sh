#!/bin/bash
# PREPARED — guarded hardening of the installed ap-trafficgen-broker file permissions (owner approval required).
#   sudo bash trafficgen-broker-harden.sh apply              -> drop-in UMask=0027 + chmod 0640 on helper log and state
#   sudo bash trafficgen-broker-harden.sh rollback <bk-dir>  -> drop-in moved to backup, previous modes restored
# Why: the helper creates /var/log/ap-trafficgen-broker.log and /var/lib/aplab/trafficgen-broker.json with systemd's default
# umask (0644, world-readable). They hold no secrets (operator names, run history, nonces) but need not be world-readable.
# Touches nothing else: no binary, key, socket, group, container, generator or Autopilot change. Starts no traffic.
set -euo pipefail
fail(){ echo "ABORT: $*" >&2; exit 2; }
[ "$(id -u)" = 0 ] || fail "run with sudo"
LOG=/var/log/ap-trafficgen-broker.log; ST=/var/lib/aplab/trafficgen-broker.json
DIR=/etc/systemd/system/ap-trafficgen-broker@.service.d; DROP=$DIR/10-umask.conf
ping_ok(){ python3 - <<'PY'
import hashlib, hmac, json, secrets, socket, time
k = open('/etc/aplab/trafficgen-broker.key', 'rb').read().strip()
q = {"action": "ping", "ts": time.time(), "nonce": secrets.token_hex(16)}
q["mac"] = hmac.new(k, json.dumps(q, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
s = socket.socket(socket.AF_UNIX); s.settimeout(30); s.connect('/run/ap-trafficgen-broker/broker.sock'); s.sendall((json.dumps(q) + "\n").encode())
r = json.loads(s.makefile().readline()); assert r.get("ok"), r; print("ping ok")
PY
}
case "${1:-}" in
apply)
  # ---- read-only preflight
  [ -x /usr/local/sbin/ap-trafficgen-broker ] && systemctl is-active --quiet ap-trafficgen-broker.socket || fail "helper not installed / socket inactive"
  [ -f "$LOG" ] && [ -f "$ST" ] || fail "helper log or state missing"
  [ ! -e "$DROP" ] || fail "$DROP already exists"
  ! docker inspect ap-trafficgen >/dev/null 2>&1 || [ "$(docker inspect -f '{{.State.Running}}' ap-trafficgen)" = false ] || fail "a generator run is active"
  EXEC0=$(grep -c ' EXEC ' "$LOG" || true)
  # ---- change
  BK=/opt/aplab/backups/tgbroker-harden-$(date -u +%Y%m%dT%H%M%SZ); install -d -m 700 "$BK"
  stat -c '%a %U:%G %n' "$LOG" "$ST" > "$BK/modes-before.txt"
  install -d -m 755 "$DIR"; printf '[Service]\nUMask=0027\n' > "$DROP"; chmod 644 "$DROP"
  systemctl daemon-reload
  chmod 640 "$LOG" "$ST"
  # ---- verify
  [ "$(systemctl show -p UMask 'ap-trafficgen-broker@x.service' | cut -d= -f2)" = 0027 ] || fail "UMask not effective (rollback: $0 rollback $BK)"
  ping_ok || fail "helper ping failed (rollback: $0 rollback $BK)"
  for f in "$LOG" "$ST"; do [ "$(stat -c '%a %U:%G' "$f")" = "640 root:root" ] || fail "$f mode after ping is $(stat -c %a "$f") (rollback: $BK)"; done
  [ "$(grep -c ' EXEC ' "$LOG" || true)" = "$EXEC0" ] || fail "helper executed a generator command"
  echo "DONE: helper log/state 0640 root:root, UMask 0027 drop-in; backup $BK" ;;
rollback)
  BK="${2:?backup dir}"; [ -f "$BK/modes-before.txt" ] || fail "backup missing"
  [ -e "$DROP" ] && mv "$DROP" "$BK/10-umask.conf.rolled-back"; rmdir "$DIR" 2>/dev/null || true
  systemctl daemon-reload
  while read -r m _ f; do [ -e "$f" ] && chmod "$m" "$f"; done < "$BK/modes-before.txt"
  ping_ok; echo "rolled back: drop-in removed, modes restored from $BK" ;;
*) fail "usage: apply | rollback <backup-dir>" ;;
esac
