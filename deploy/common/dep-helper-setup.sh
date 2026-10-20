#!/bin/bash
# Install the scoped dependency helper (root). Usage: dep-helper-setup.sh <role> ; pubkey on stdin.
set -euo pipefail
ROLE=$1; case $ROLE in ai-services|agent-a|agent-b) ;; *) echo "bad role"; exit 2;; esac
install -d -m 755 /etc/aplab && echo "$ROLE" > /etc/aplab/role
[ -f /etc/aplab/profile ] || echo baseline > /etc/aplab/profile
install -d -m 755 /opt/aplab/profiles && rsync -a --delete /opt/aplab/src/deploy/profiles/$ROLE/ /opt/aplab/profiles/$ROLE/
chown -R root:root /opt/aplab/profiles && chmod -R go-w /opt/aplab/profiles
install -m 755 -o root -g root /opt/aplab/src/deploy/common/ap-dep-apply /usr/local/sbin/ap-dep-apply
id apdeploy >/dev/null 2>&1 || useradd -r -m -d /var/lib/apdeploy -s /bin/sh apdeploy
passwd -l apdeploy >/dev/null
install -d -m 700 -o apdeploy -g apdeploy /var/lib/apdeploy/.ssh
KEY=$(cat)
echo "restrict,command=\"sudo -n /usr/local/sbin/ap-dep-apply\",from=\"192.0.2.60\" $KEY" > /var/lib/apdeploy/.ssh/authorized_keys
chown apdeploy:apdeploy /var/lib/apdeploy/.ssh/authorized_keys && chmod 600 /var/lib/apdeploy/.ssh/authorized_keys
cat > /etc/sudoers.d/91-apdeploy <<'S'
Defaults!/usr/local/sbin/ap-dep-apply env_keep += "SSH_ORIGINAL_COMMAND"
apdeploy ALL=(root) NOPASSWD: /usr/local/sbin/ap-dep-apply
S
chmod 440 /etc/sudoers.d/91-apdeploy && visudo -cf /etc/sudoers.d/91-apdeploy >/dev/null
if [ "$ROLE" != ai-services ]; then   # lab DNS for aplab.internal only (split DNS); names still resolve to baseline addresses
  install -d /etc/systemd/resolved.conf.d
  printf '[Resolve]\nDNS=192.0.2.63\nDomains=~aplab.internal\n' > /etc/systemd/resolved.conf.d/aplab.conf
  systemctl restart systemd-resolved
fi
/usr/local/sbin/ap-dep-apply status
