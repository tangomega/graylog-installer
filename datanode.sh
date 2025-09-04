#!/usr/bin/env bash
# datanode.sh: Graylog Data Node installer for Ubuntu 24.04
# Installs, configures, and verifies Graylog Data Node with OpenSearch.
# Sources:
# - Graylog Data Node config: https://go2docs.graylog.org/current/setting_up_graylog/data_node_configuration_file.htm
# - Graylog Ubuntu install: https://go2docs.graylog.org/current/downloading_and_installing_graylog/ubuntu_installation.htm
# - OpenSearch requirements: https://opensearch.org/docs/latest/

set -euo pipefail
IFS=$'\n\t'

LOG="/var/log/datanode-install.log"
touch "$LOG" && chmod 600 "$LOG" && chown root:root "$LOG"
exec > >(tee -a "$LOG") 2>&1

# === Helper functions ===
require_root() {
  if [[ "$(id -u)" != 0 ]]; then
    echo "❌ Must run as root (use sudo)." >&2
    exit 1
  fi
}

apt_install_if_missing() {
  local pkgs=("$@")
  local to_install=()
  for pkg in "${pkgs[@]}"; do
    if ! dpkg -s "$pkg" &>/dev/null; then
      to_install+=("$pkg")
    fi
  done
  if [[ ${#to_install[@]} -gt 0 ]]; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${to_install[@]}"
  fi
}

backup_file() {
  local file="${1:-}"
  if [[ -n "$file" && -f "$file" ]]; then
    cp -p "$file" "${file}.bak.$(date +%s)"
    echo "ℹ️ Backed up $file"
  fi
}

# === Preflight ===
require_root
apt_install_if_missing apt-transport-https openjdk-17-jre-headless curl wget gnupg lsb-release jq

# === Add Graylog repo (if missing) ===
if ! grep -q "packages.graylog2.org" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
  wget -q https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb -O /tmp/graylog-repo.deb
  dpkg -i /tmp/graylog-repo.deb
  apt-get update -y
fi

# === Install Data Node ===
apt_install_if_missing graylog-datanode

# === System settings for OpenSearch ===
echo "vm.max_map_count=262144" > /etc/sysctl.d/99-graylog-datanode.conf
sysctl -p /etc/sysctl.d/99-graylog-datanode.conf

# === Configure datanode.conf ===
DN_CONF="/etc/graylog/datanode/datanode.conf"
mkdir -p "$(dirname "$DN_CONF")"
backup_file "$DN_CONF"
touch "$DN_CONF"

# Generate password_secret if missing
if ! grep -q "^password_secret" "$DN_CONF"; then
  server_secret=$(openssl rand -hex 64)
  echo "password_secret = $server_secret" >> "$DN_CONF"
  echo "ℹ️ Generated new password_secret"
else
  server_secret=$(awk -F'=' '/^password_secret/ {gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2}' "$DN_CONF")
fi

# Prompt for admin password and generate hash if missing
if ! grep -q "^root_password_sha2" "$DN_CONF"; then
  read -s -p "Enter Graylog admin password: " admin_pass
  echo
  read -s -p "Confirm Graylog admin password: " admin_pass2
  echo
  if [[ "$admin_pass" != "$admin_pass2" ]]; then
    echo "❌ Passwords do not match. Aborting."
    exit 1
  fi
  root_password_sha2=$(echo -n "$admin_pass" | sha256sum | awk '{print $1}')
  echo "root_password_sha2 = $root_password_sha2" >> "$DN_CONF"
  echo "ℹ️ Stored root_password_sha2"
fi

# Ensure required fields exist
grep -q "^data_dir" "$DN_CONF" || echo "data_dir = /var/lib/graylog-datanode" >> "$DN_CONF"
grep -q "^http_bind_address" "$DN_CONF" || echo "http_bind_address = 0.0.0.0:8999" >> "$DN_CONF"
grep -q "^opensearch_network_host" "$DN_CONF" || echo "opensearch_network_host = 0.0.0.0" >> "$DN_CONF"
grep -q "^opensearch_heap" "$DN_CONF" || echo "opensearch_heap = 1g" >> "$DN_CONF"
grep -q "^mongodb_uri" "$DN_CONF" || echo "mongodb_uri = mongodb://localhost:27017/graylog" >> "$DN_CONF"

chown graylog:graylog "$DN_CONF"

# === Start service ===
systemctl daemon-reexec
systemctl enable --now graylog-datanode

# === Verification ===
echo "🔍 Verifying Graylog Data Node service..."

# 1. systemd status
if ! systemctl is-active --quiet graylog-datanode; then
  echo "❌ graylog-datanode service not running."
  exit 1
fi
echo "✅ graylog-datanode systemd service is active."

# 2. Logs check
if journalctl -u graylog-datanode -n 100 --no-pager | grep -qi "error"; then
  echo "⚠️ Detected errors in datanode logs, check with:"
  echo "    sudo journalctl -u graylog-datanode -n 200 --no-pager"
else
  echo "✅ No critical errors detected in logs."
fi

# 3. Ports
sleep 10
if ss -tulpn | grep -q ":9200"; then
  echo "✅ OpenSearch is listening on port 9200"
else
  echo "❌ OpenSearch is NOT listening on port 9200"
  exit 1
fi

if ss -tulpn | grep -q ":8999"; then
  echo "✅ Data Node REST API is listening on port 8999"
else
  echo "❌ Data Node REST API is NOT listening on port 8999"
  exit 1
fi

echo "🎉 Graylog Data Node installation and verification complete."

# === Cleanup function ===
cleanup() {
  echo "⚠️ This will REMOVE Graylog Data Node completely."
  read -p "Are you sure? (y/N): " confirm
  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    systemctl stop graylog-datanode || true
    apt-get purge -y graylog-datanode
    apt-get autoremove -y
    apt-get clean
    rm -rf /etc/graylog/datanode /var/lib/graylog-datanode /var/log/graylog-datanode
    echo "🗑️ Graylog Data Node purged."
  else
    echo "Cleanup canceled."
  fi
}
