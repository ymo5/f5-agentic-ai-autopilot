#!/bin/bash
# Idempotent base host setup for AP Ubuntu VMs (run as root via sudo).
# OS updates, Docker (Ubuntu packages) with iptables/ip-forward DISABLED so the host nftables
# policy and ip_forward=0 remain authoritative (all lab containers use host networking).
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get -y -q -o Dpkg::Options::=--force-confold full-upgrade
apt-get -y -q install docker.io docker-compose-v2 unattended-upgrades dnsutils
install -d -m 755 /etc/docker
install -m 644 /tmp/aplab-deploy/common/daemon.json /etc/docker/daemon.json
systemctl enable --now docker
systemctl restart docker
# The docker.io postinst starts dockerd once with defaults (which enables forwarding) before our
# daemon.json exists; re-apply the persisted ip_forward=0 and verify.
sysctl --system >/dev/null
[ "$(sysctl -n net.ipv4.ip_forward)" = 0 ] || { echo "ERROR: ip_forward still enabled"; exit 1; }
# nftables: allow role-specific rule files to append to the base table.
grep -q 'include "/etc/nftables.d/\*.nft"' /etc/nftables.conf || echo 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf
install -d -m 755 /etc/nftables.d
if [ -f /tmp/aplab-role.nft ]; then install -m 644 /tmp/aplab-role.nft /etc/nftables.d/role.nft; fi
nft -c -f /etc/nftables.conf && systemctl restart nftables
echo "ip_forward=$(sysctl -n net.ipv4.ip_forward)"
