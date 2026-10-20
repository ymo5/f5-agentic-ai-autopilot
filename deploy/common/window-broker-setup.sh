#!/bin/bash
# One-time setup of the scoped live-window broker on AP-AUTOPILOT-01 (run as root from /opt/aplab/src).
#   * group apwin (gid 10020): only the autopilot-deployer container joins it (compose group_add)
#   * HMAC key /etc/aplab/window-broker.key (root 0600) + read-only copy for the deployer secrets
#   * /usr/local/sbin/ap-window-broker + systemd socket (root:apwin 0660) and per-connection service
# Idempotent. Does not open a window, does not touch BIG-IP or other hosts.
set -euo pipefail
SRC=/opt/aplab/src/deploy/common
getent group apwin >/dev/null || groupadd -g 10020 apwin
install -d -m 755 -o root -g root /etc/aplab /var/lib/aplab
if [ ! -s /etc/aplab/window-broker.key ]; then
  umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/aplab/window-broker.key
fi
chmod 600 /etc/aplab/window-broker.key
# deployer secret copy (same ownership/permissions model as the other files in the deployer secrets directory)
ref=$(ls -n /opt/aplab/secrets/deployer/deployer_token | awk '{print $3":"$4}')
install -m 440 -o "${ref%%:*}" -g "${ref##*:}" /etc/aplab/window-broker.key /opt/aplab/secrets/deployer/window_broker_key
install -m 755 -o root -g root "$SRC/ap-window-broker" /usr/local/sbin/ap-window-broker
install -m 755 -o root -g root "$SRC/ap-live-window" /usr/local/sbin/ap-live-window
cat > /etc/systemd/system/ap-window-broker.socket <<'EOF'
[Unit]
Description=Autopilot live-window broker socket (deployer container only)
[Socket]
ListenStream=/run/ap-window/broker.sock
SocketUser=root
SocketGroup=apwin
SocketMode=0660
DirectoryMode=0755
Accept=yes
MaxConnections=4
[Install]
WantedBy=sockets.target
EOF
cat > /etc/systemd/system/ap-window-broker@.service <<'EOF'
[Unit]
Description=Autopilot live-window broker request
[Service]
Type=simple
ExecStart=/usr/local/sbin/ap-window-broker
StandardInput=socket
StandardOutput=socket
StandardError=journal
User=root
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
RuntimeMaxSec=120
EOF
systemctl daemon-reload
systemctl enable --now ap-window-broker.socket
ls -la /run/ap-window/
echo "window broker installed"
