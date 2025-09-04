#!/usr/bin/env bash
# install-graylog-datanode.sh
# Fault-tolerant, idempotent installer for Graylog DataNode (with embedded OpenSearch) on Ubuntu Server 24.04
# Requires MongoDB to be pre-installed and running
# Run with sudo

# Documentation and Citations:
# - Graylog DataNode: https://docs.graylog.org/docs/datanode
# - OpenSearch Prerequisites (vm.max_map_count): https://opensearch.org/docs/latest/install-and-configure/install-opensearch/index/#important-settings
# - MongoDB Configuration: https://www.mongodb.com/docs/manual/reference/configuration-options/#net-options
# - Graylog Prerequisites: https://docs.graylog.org/docs/prerequisites
# - JVM Settings: https://docs.graylog.org/docs/prerequisites#jvm-settings

# Five most load-bearing facts:
# 1. Graylog DataNode requires OpenJDK 17 or later.
# 2. DataNode embeds OpenSearch and requires vm.max_map_count=262144.
# 3. MongoDB must be running and accessible at mongodb://localhost:27017/graylog.
# 4. DataNode must expose OpenSearch API (0.0.0.0:9200) and REST API (0.0.0.0:8999).
# 5. Heap size should be 25-50% of system RAM, capped at 16GB.

set -euo pipefail
IFS=$'\n\t'

LOG="/var/log/graylog-datanode-install.log"
touch "$LOG"
exec > >(tee -a "$LOG") 2>&1

DATANODE_CONF="/etc/graylog/datanode/datanode.conf"
GRAYLOG_DATANODE_DATA_DIR="/var/lib/graylog-datanode"
GD_REPO_DEB_URL="https://packages.graylog2.org/repo/packages/graylog-repository_latest.deb"
GITHUB_URL="https://raw.githubusercontent.com/example/repo/main/install-graylog-datanode.sh"  # Replace with actual URL

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (sudo)." >&2
    exit 1
  fi
}

apt_install_if_missing() {
  local pkgs=("$@")
  local miss=()
  for p in "${pkgs[@]}"; do
    if ! dpkg -s "$p" >/dev/null 2>&1; then
      miss+=("$p")
    fi
  done
  if [ "${#miss[@]}" -gt 0 ]; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${miss[@]}"
  fi
}

ensure_conf_value() {
  local file="$1" key="$2" value="$3"
  mkdir -p "$(dirname "$file")"
  [ -f "$file" ] || echo "# Created by installer" > "$file"
  if grep -qE "^\s*$key\s*=" "$file"; then
    sed -i -E "s|^\s*$key\s*=.*|$key = $value|" "$file"
    echo "Updated $key in $file"
  else
    echo "$key = $value" >> "$file"
    echo "Added $key to $file"
  fi
}

extract_conf_value() {
  local file="$1" key="$2"
  awk -F'=' -v k="$key" '$0 ~ "^[ \t]*"k"[ \t]*=" { gsub(/[ \t]+/,"",$2); print $2; exit }' "$file" 2>/dev/null || true
}

ensure_password_secret() {
  local secret
  secret=$(extract_conf_value "$DATANODE_CONF" "password_secret")
  if [ -n "$secret" ]; then
    echo "password_secret already present in datanode.conf"
    return
  fi
  secret=$(openssl rand -hex 48)
  ensure_conf_value "$DATANODE_CONF" "password_secret" "$secret"
  echo "Generated and set new password_secret"
}

ensure_datanode_binds() {
  ensure_conf_value "$DATANODE_CONF" "opensearch_network_host" "0.0.0.0"
  ensure_conf_value "$DATANODE_CONF" "opensearch_http_bind_address" "0.0.0.0:9200"
  ensure_conf_value "$DATANODE_CONF" "opensearch_transport_bind_address" "0.0.0.0:9300"
  ensure_conf_value "$DATANODE_CONF" "http_bind_address" "0.0.0.0:8999"
  ensure_conf_value "$DATANODE_CONF" "mongodb_uri" "mongodb://localhost:27017/graylog"
}

ensure_data_dir() {
  mkdir -p "$GRAYLOG_DATANODE_DATA_DIR/opensearch"
  chown -R graylog:graylog "$GRAYLOG_DATANODE_DATA_DIR" || true
  ensure_conf_value "$DATANODE_CONF" "opensearch_data_location" "$GRAYLOG_DATANODE_DATA_DIR/opensearch"
}

detect_and_set_heap() {
  local total_mem_mb heap_mb
  total_mem_mb=$(free -m | awk '/^Mem:/ {print $2}')
  heap_mb=$(( total_mem_mb / 4 ))  # 25% for DataNode JVM
  heap_mb=${heap_mb:-1024}  # Min 1GB
  if [ "$heap_mb" -gt 16384 ]; then heap_mb=16384; fi  # Max 16GB
  echo "Detected total RAM: ${total_mem_mb}MB. Setting DataNode heap to ${heap_mb}MB"
  ensure_conf_value "$DATANODE_CONF" "opensearch_heap" "${heap_mb}m"
}

set_vm_max_map_count() {
  if ! sysctl -a 2>/dev/null | grep -q "vm.max_map_count = 262144"; then
    sysctl -w vm.max_map_count=262144 || true
    echo "vm.max_map_count=262144" > /etc/sysctl.d/99-graylog-datanode.conf || true
    sysctl --system >/dev/null || true
    echo "Set vm.max_map_count=262144"
  else
    echo "vm.max_map_count already set to 262144"
  fi
}

start_and_wait() {
  local svc="$1"
  systemctl enable "$svc" --now || { echo "Failed to enable/start $svc"; return 1; }
  for i in {1..8}; do
    if systemctl is-active --quiet "$svc"; then
      echo "$svc active"
      return 0
    fi
    echo "Waiting for $svc to start ($i/8)..."
    sleep 4
  done
  echo "Service $svc did not start in time."
  return 1
}

basic_checks() {
  echo
  echo "=== DataNode Checks ==="
  echo "systemd state:"
  systemctl status graylog-datanode --no-pager || true
  echo
  echo "Listening ports (9200, 8999, 9300):"
  ss -tulpen | grep -E ':(9200|8999|9300)' || true
  echo
  echo "OpenSearch health:"
  curl -sS --max-time 3 http://127.0.0.1:9200/_cluster/health || echo "No response from 9200"
}

generate_troubleshooting_log() {
  local log_file="/var/log/graylog-datanode-troubleshoot-$(date +%Y%m%d%H%M%S).log"
  echo "Generating troubleshooting log: $log_file"

  {
    echo "=== Graylog DataNode Troubleshooting Log ==="
    echo "Generated: $(date)"
    echo

    echo "=== System Information ==="
    echo "OS Version:"
    lsb_release -a 2>/dev/null || echo "lsb_release not available"
    echo
    echo "Kernel Version:"
    uname -a
    echo
    echo "Total RAM (MB):"
    free -m | awk '/^Mem:/ {print $2}'
    echo
    echo "CPU Info:"
    lscpu | grep -E 'Model name|Socket|Core|Thread|CPU\(s\)'
    echo

    echo "=== Package Versions ==="
    echo "OpenJDK Version:"
    java -version 2>&1 || echo "Java not installed"
    echo
    echo "MongoDB Version:"
    mongod --version 2>/dev/null || echo "MongoDB not installed"
    echo
    echo "Graylog DataNode Version:"
    dpkg -l | grep graylog-datanode 2>/dev/null || echo "Graylog DataNode not installed"
    echo

    echo "=== Service Status ==="
    echo "MongoDB Service:"
    systemctl status mongod --no-pager 2>/dev/null || echo "MongoDB service not found"
    echo
    echo "Graylog DataNode Service:"
    systemctl status graylog-datanode --no-pager 2>/dev/null || echo "Graylog DataNode service not found"
    echo

    echo "=== Configuration Files ==="
    echo "MongoDB Config (/etc/mongod.conf):"
    if [ -f "/etc/mongod.conf" ]; then
      cat /etc/mongod.conf || echo "Failed to read /etc/mongod.conf"
    else
      echo "/etc/mongod.conf not found"
    fi
    echo
    echo "Graylog DataNode Config (/etc/graylog/datanode/datanode.conf):"
    if [ -f "/etc/graylog/datanode/datanode.conf" ]; then
      sed 's/password_secret\s*=.*/password_secret = [REDACTED]/' /etc/graylog/datanode/datanode.conf || echo "Failed to read /etc/graylog/datanode/datanode.conf"
    else
      echo "/etc/graylog/datanode/datanode.conf not found"
    fi
    echo
    echo "Sysctl Config (/etc/sysctl.d/99-graylog-datanode.conf):"
    if [ -f "/etc/sysctl.d/99-graylog-datanode.conf" ]; then
      cat /etc/sysctl.d/99-graylog-datanode.conf || echo "Failed to read /etc/sysctl.d/99-graylog-datanode.conf"
    else
      echo "/etc/sysctl.d/99-graylog-datanode.conf not found"
    fi
    echo

    echo "=== System Logs ==="
    echo "MongoDB Logs (last 50 lines):"
    journalctl -u mongod -n 50 --no-pager 2>/dev/null || echo "No MongoDB logs available"
    echo
    echo "Graylog DataNode Logs (last 50 lines):"
    journalctl -u graylog-datanode -n 50 --no-pager 2>/dev/null || echo "No Graylog DataNode logs available"
    echo

    echo "=== Network Status ==="
    echo "Listening Ports (9200, 8999, 9300):"
    ss -tulpen | grep -E ':(9200|8999|9300)' 2>/dev/null || echo "No relevant ports listening"
    echo
    echo "OpenSearch Health Check:"
    curl -sS --max-time 3 http://127.0.0.1:9200/_cluster/health 2>/dev/null || echo "No response from OpenSearch (port 9200)"
    echo
    echo "DataNode REST API Check:"
    curl -sS --max-time 3 http://127.0.0.1:8999 2>/dev/null || echo "No response from DataNode REST API (port 8999)"
    echo

    echo "=== End of Troubleshooting Log ==="
  } > "$log_file" 2>&1

  echo "Troubleshooting log generated at $log_file"
  echo "Please share this file for support."
}

cleanup() {
  echo "WARNING: This will remove Graylog DataNode and all its data. Continue? [y/N]"
  read -r confirm
  if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "Cleanup aborted."
    return
  fi
  systemctl stop graylog-datanode || true
  apt-get purge -y graylog-datanode || true
  rm -rf "$GRAYLOG_DATANODE_DATA_DIR" "$DATANODE_CONF" /etc/sysctl.d/99-graylog-datanode.conf
  apt-get autoremove -y || true
  echo "Cleanup complete."
}

check_for_update() {
  if [ "${UPDATE:-false}" = "true" ]; then
    echo "Checking for updated script at $GITHUB_URL..."
    local tmp_script
    tmp_script=$(mktemp)
    if curl -fsSL "$GITHUB_URL" -o "$tmp_script"; then
      if cmp -s "$0" "$tmp_script"; then
        echo "No updates available."
        rm -f "$tmp_script"
      else
        echo "Update available. Replacing script..."
        mv "$tmp_script" "$0"
        chmod +x "$0"
        echo "Script updated. Please re-run."
        exit 0
      fi
    else
      echo "Failed to fetch update. Continuing with current script."
      rm -f "$tmp_script"
    fi
  fi
}

main() {
  require_root
  echo "Starting Graylog DataNode installer"
  check_for_update

  # Install essential packages
  apt_install_if_missing gnupg curl wget apt-transport-https openssl ca-certificates jq openjdk-17-jre-headless

  # Verify MongoDB is running
  if ! systemctl is-active --quiet mongod; then
    echo "MongoDB is not running. Please ensure MongoDB is installed and running."
    echo "Remediation: Install MongoDB with 'sudo apt-get install mongodb-org' and start with 'sudo systemctl start mongod'"
    exit 1
  fi

  # Install Graylog repo
  if ! dpkg -l | grep -q graylog; then
    wget -q "$GD_REPO_DEB_URL" -O /tmp/graylog-repo.deb
    dpkg -i /tmp/graylog-repo.deb || true
    apt-get update -y
  fi

  # Install DataNode
  apt_install_if_missing graylog-datanode

  # Configure kernel
  set_vm_max_map_count

  # Configure DataNode
  ensure_password_secret
  ensure_datanode_binds
  ensure_data_dir
  detect_and_set_heap

  # Start and verify
  systemctl daemon-reload
  start_and_wait graylog-datanode || {
    echo "graylog-datanode failed to start."
    echo "Remediation: Check logs with 'journalctl -u graylog-datanode -n 200 --no-pager'"
    echo "Config file: $DATANODE_CONF"
    exit 1
  }

  # Perform checks
  basic_checks

  echo
  echo "Graylog DataNode installation complete. OpenSearch API at http://<server-ip>:9200"
  echo "DataNode REST API at http://<server-ip>:8999"
}

# Parse optional update flag
UPDATE=false
while getopts "u" opt; do
  case $opt in
    u) UPDATE=true ;;
    *) echo "Usage: $0 [-u]"; exit 1 ;;
  esac
done

main "$@"
