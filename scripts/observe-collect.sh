#!/bin/zsh
# OBSERVE collector (operator workstation): read-only iControl REST GETs against one or more BIG-IP devices, then upload
# one snapshot per device to Autopilot (or only write it locally with --no-upload).
#
# Security model (unchanged from v1):
#   * GET requests only to BIG-IP; every request pins the device's TLS public key (--pinnedpubkey) — a device without a
#     pin is refused;
#   * credentials come from the macOS Keychain and reach curl only through process-substitution config files
#     (never argv, files or logs); the Autopilot operator token likewise;
#   * snapshots contain BIG-IP responses only (no credentials); secret-bearing fields are redacted before anything is written
#     (passphrases/passwords/secrets/tokens, Authorization headers in strings, iRule source, monitor send/receive strings);
#   * curl ignores ~/.curlrc (-q) and proxy settings, speaks HTTPS only (--proto =https, TLS >= 1.2) and never follows
#     redirects; a TLS/pin failure stops that device immediately (no further requests, no snapshot, no retry, no fallback);
#   * the first request (GET sys/version) is the credential check: HTTP 401 there stops the device after ONE attempt, so a
#     wrong password cannot lock the account; a later 401/403 on a single endpoint is a per-resource authorization denial
#     and is recorded as permission_denied.
#
# Usage: scripts/observe-collect.sh [--no-upload] [--out DIR] [LABEL ...]
#   Devices:  $OBSERVE_CONFIG_DIR/observe-devices.conf  (default config/): "label  host  pin_var  keychain_service" per line
#   Pins:     $OBSERVE_CONFIG_DIR/f5-tls-pins.env       (pin_var names a variable there, value sha256//...)
#   Upload:   $OBSERVE_CONFIG_DIR/observe-collector.env  (AUTOPILOT_URL, AUTOPILOT_TOKEN_ITEM)
#   LABEL ... restricts the run to those devices (default: all devices in the file).
set -uo pipefail
zmodload zsh/datetime
D="${0:A:h:h}"; CONF="${OBSERVE_CONFIG_DIR:-$D/config}"
UPLOAD=1; OUT=""; typeset -a ONLY
while (( $# )); do
  case "$1" in
    --no-upload) UPLOAD=0 ;;
    --out) shift; OUT="${1:-}" ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    -*) print -u2 "unknown option $1"; exit 2 ;;
    *) ONLY+=("$1") ;;
  esac
  shift
done
[[ -r "$CONF/observe-devices.conf" ]] || { print -u2 "missing $CONF/observe-devices.conf"; exit 2; }
[[ -r "$CONF/f5-tls-pins.env" ]] && source "$CONF/f5-tls-pins.env"
AUTOPILOT_URL=""; AUTOPILOT_TOKEN_ITEM=""
[[ -r "$CONF/observe-collector.env" ]] && source "$CONF/observe-collector.env"
if (( UPLOAD )) && [[ -z "$AUTOPILOT_URL" || -z "$AUTOPILOT_TOKEN_ITEM" ]]; then
  print -u2 "upload needs AUTOPILOT_URL and AUTOPILOT_TOKEN_ITEM in $CONF/observe-collector.env (or use --no-upload)"; exit 2
fi
[[ -n "$OUT" ]] && { mkdir -p "$OUT" && chmod 700 "$OUT" || exit 2; }

# Read-only endpoints: sources/observe.py ENDPOINTS + PLACEMENT_ENDPOINTS (a test keeps this list equal to them).
typeset -A EP=(version /mgmt/tm/sys/version provision /mgmt/tm/sys/provision global /mgmt/tm/sys/global-settings
  vlan /mgmt/tm/net/vlan self /mgmt/tm/net/self virtual "/mgmt/tm/ltm/virtual?expandSubcollections=true"
  virtual_stats /mgmt/tm/ltm/virtual/stats pool "/mgmt/tm/ltm/pool?expandSubcollections=true" pool_stats /mgmt/tm/ltm/pool/stats
  monitor_http /mgmt/tm/ltm/monitor/http monitor_https /mgmt/tm/ltm/monitor/https rule /mgmt/tm/ltm/rule
  persistence_universal /mgmt/tm/ltm/persistence/universal clientssl /mgmt/tm/ltm/profile/client-ssl as3 /mgmt/shared/appsvcs/info
  log_destination /mgmt/tm/sys/log-config/destination/management-port
  route /mgmt/tm/net/route failover_status /mgmt/tm/cm/failover-status
  device_group "/mgmt/tm/cm/device-group?expandSubcollections=true" memory /mgmt/tm/sys/memory cpu /mgmt/tm/sys/cpu)

cq(){ print -rn -- "${1//\\/\\\\}" | sed 's/"/\\"/g'; }
T=""; trap '[[ -n "$T" ]] && rm -rf "$T"' EXIT INT TERM
rc=0; seen=0
while read -r label host pinvar svc _rest; do
  [[ -z "${label:-}" || "$label" == \#* ]] && continue
  (( ${#ONLY} )) && (( ! ${ONLY[(Ie)$label]} )) && continue
  seen=$((seen + 1))
  if [[ ! "$label" =~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$' || -z "${host:-}" || -z "${svc:-}" ]]; then
    print -u2 "[$label] invalid device line (label host pin_var keychain_service)"; rc=1; continue
  fi
  PIN="${(P)pinvar:-}"
  if [[ "$PIN" != sha256//* ]]; then print -u2 "[$label] no pinned public key in \$$pinvar — refusing to connect"; rc=1; continue; fi
  BU=$(security find-generic-password -s "$svc" 2>/dev/null | sed -nE 's/^ *"acct"<blob>="(.*)"$/\1/p')
  BP=$(security find-generic-password -s "$svc" -w 2>/dev/null)
  if [[ -z "$BU" || -z "$BP" ]]; then print -u2 "[$label] Keychain item '$svc' not found"; unset BP; rc=1; continue; fi
  T=$(mktemp -d); chmod 700 "$T"
  START=$EPOCHREALTIME; abort=""
  for k in version ${(ok)EP:#version}; do        # fixed order; sys/version first = credential check
    p="${EP[$k]}"
    # -k skips CA/host-name validation ONLY; the pinned public key is still enforced (curl exit 90 on mismatch)
    res=$(curl -q -s -k --pinnedpubkey "$PIN" --proto '=https' --tlsv1.2 --noproxy '*' --max-time 20 \
               -K <(printf 'user = "%s:%s"\n' "$(cq "$BU")" "$(cq "$BP")") \
               -o "$T/$k.body" -w '%{http_code} %{time_total}' "https://$host$p")
    ce=$?
    if (( ce != 0 )); then
      why=""; (( ce == 90 )) && why=": pinned public key mismatch"; (( ce == 35 || ce == 60 )) && why=": TLS handshake failed"
      abort="TLS/transport failure on GET $p (curl exit $ce$why)"; break
    fi
    if [[ "$k" == version && "${res%% *}" == 401 ]]; then
      abort="authentication failed (HTTP 401) on the credential check GET $p — stopping to avoid account lockout"; break
    fi
    print -r -- "${res%% *}" > "$T/$k.code"; print -r -- "${res##* }" > "$T/$k.time"
    print "[$label] GET $p -> ${res%% *} (${res##* } s)"
  done
  unset BP
  if [[ -n "$abort" ]]; then
    print -u2 "[$label] $abort — no further requests, nothing written or uploaded"; rm -rf "$T"; T=""; rc=1; continue
  fi
  SNAP=$(python3 -I -c '
import json, os, re, sys
d, label, host, start = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
SECRET = re.compile(r"(?i)(pass(phrase|word)?|secret|token|psk|shared[-_]?key|private[-_]?key)$")
DROP = {"apiAnonymous": "iRule source", "send": "monitor send string", "recv": "monitor receive string",
        "recvDisable": "monitor receive-disable string"}
AUTH = re.compile(r"(?i)(authorization|proxy-authorization|cookie|x-f5-auth-token)\s*:\s*[^\\\r\n]+")
def redact(o):
    if isinstance(o, dict):
        return {k: ("[REDACTED]" if SECRET.search(k) and v not in (None, "", "none") else
                    f"[REDACTED: {DROP[k]} not collected]" if k in DROP and isinstance(v, str) else redact(v)) for k, v in o.items()}
    if isinstance(o, list):
        return [redact(v) for v in o]
    if isinstance(o, str):
        return AUTH.sub(lambda m: m.group(1) + ": [REDACTED]", o)
    return o
out, timings = {}, {}
for f in sorted(os.listdir(d)):
    if not f.endswith(".code"):
        continue
    k = f[:-5]
    try:
        body = json.load(open(os.path.join(d, k + ".body")))
    except (ValueError, OSError):
        body = None
    code = int((open(os.path.join(d, f)).read().strip() or "0").split()[0] or 0)
    out[k] = {"status": code, "body": redact(body)}
    try:
        if code:
            timings[k] = round(float(open(os.path.join(d, k + ".time")).read().strip()), 3)
    except (ValueError, OSError):
        pass
out["_meta"] = {"device": {"label": label, "mgmt": host}, "collected_at": round(start, 3), "timings_s": timings,
                "collector": "observe-collect.sh/2.1", "redaction": "secret-named fields, auth headers, iRule source, monitor send/recv"}
print(json.dumps(out))' "$T" "$label" "$host" "$START")
  rm -rf "$T"; T=""
  if [[ -n "$OUT" ]]; then
    f="$OUT/$label-${START%.*}.json"; ( umask 077; print -r -- "$SNAP" > "$f" ); print "[$label] wrote $f"
  fi
  if (( UPLOAD )); then
    TOK=$(security find-generic-password -s "$AUTOPILOT_TOKEN_ITEM" -w 2>/dev/null)
    [[ -z "$TOK" ]] && { print -u2 "[$label] Keychain item '$AUTOPILOT_TOKEN_ITEM' not found — not uploaded"; rc=1; continue; }
    print -r -- "$SNAP" | curl -q -s -X POST "$AUTOPILOT_URL/api/observe/snapshot" -H 'content-type: application/json' \
      -K <(printf 'header = "Authorization: Bearer %s"\n' "$TOK") --data-binary @- ; echo
    unset TOK
  fi
done < "$CONF/observe-devices.conf"
(( seen )) || { print -u2 "no matching device in $CONF/observe-devices.conf"; exit 2; }
exit $rc
