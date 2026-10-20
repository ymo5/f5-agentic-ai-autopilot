#!/bin/bash
# Install / remove the scoped Traffic Generator broker on AP-AUTOPILOT-01 (modelled on window-broker-setup.sh).
#   sudo bash trafficgen-broker-setup.sh install <dir-with-ap-trafficgen-broker>
#   sudo bash trafficgen-broker-setup.sh uninstall <backup-dir>
# install: group aptgctl (gid 10021; only the autopilot-deployer container joins it via its compose override), HMAC key
# /etc/aplab/trafficgen-broker.key (root 0600) + read-only copy in the deployer secrets, /usr/local/sbin/ap-trafficgen-broker,
# systemd socket /run/ap-trafficgen-broker/broker.sock (root:aptgctl 0660, Accept=yes) + per-connection service.
# Starts no traffic; does not touch ap-trafficgen, the generator image, Autopilot containers, BIG-IP or other hosts.
set -euo pipefail
fail(){ echo "ABORT: $*" >&2; exit 2; }
[ "$(id -u)" = 0 ] || fail "run with sudo"
MODE="${1:?install|uninstall}"; ARG="${2:?dir}"
KEY=/etc/aplab/trafficgen-broker.key; DKEY=/opt/aplab/secrets/deployer/trafficgen_broker_key; BIN=/usr/local/sbin/ap-trafficgen-broker
SOCK=/etc/systemd/system/ap-trafficgen-broker.socket; SVC=/etc/systemd/system/ap-trafficgen-broker@.service
if [ "$MODE" = uninstall ]; then
  BK="$ARG"; install -d -m 700 "$BK"
  systemctl disable --now ap-trafficgen-broker.socket 2>/dev/null || true
  for f in $SOCK $SVC $BIN $KEY $DKEY /var/lib/aplab/trafficgen-broker.json /var/log/ap-trafficgen-broker.log; do [ -e $f ] && mv $f "$BK/" || true; done
  systemctl daemon-reload
  getent group aptgctl >/dev/null && groupdel aptgctl || true
  echo "trafficgen broker removed; files moved to $BK"; exit 0
fi
SRC="$ARG"; [ -f "$SRC/ap-trafficgen-broker" ] || fail "broker source missing"
[ -x /usr/local/sbin/ap-trafficgen ] || fail "ap-trafficgen not installed"
for f in $BIN $SOCK $SVC $KEY $DKEY; do [ ! -e $f ] || fail "$f already exists"; done
! getent group 10021 >/dev/null || [ "$(getent group 10021 | cut -d: -f1)" = aptgctl ] || fail "gid 10021 used by another group"
ref=$(ls -n /opt/aplab/secrets/deployer/deployer_token | awk '{print $3":"$4}')
getent group aptgctl >/dev/null || groupadd -g 10021 aptgctl
install -d -m 755 -o root -g root /etc/aplab /var/lib/aplab
( umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > $KEY ); chmod 600 $KEY
install -m 440 -o "${ref%%:*}" -g "${ref##*:}" $KEY $DKEY
install -m 755 -o root -g root "$SRC/ap-trafficgen-broker" $BIN
cat > $SOCK <<'EOF'
[Unit]
Description=Autopilot Traffic Generator broker socket (deployer container only)
[Socket]
ListenStream=/run/ap-trafficgen-broker/broker.sock
SocketUser=root
SocketGroup=aptgctl
SocketMode=0660
DirectoryMode=0755
Accept=yes
MaxConnections=4
[Install]
WantedBy=sockets.target
EOF
cat > $SVC <<'EOF'
[Unit]
Description=Autopilot Traffic Generator broker request
[Service]
Type=simple
ExecStart=/usr/local/sbin/ap-trafficgen-broker
StandardInput=socket
StandardOutput=socket
StandardError=journal
User=root
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
RuntimeMaxSec=240
UMask=0027
EOF
systemctl daemon-reload
systemctl enable --now ap-trafficgen-broker.socket
ls -la /run/ap-trafficgen-broker/
echo "trafficgen broker installed (no traffic started)"
