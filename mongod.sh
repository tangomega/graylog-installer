#!/usr/bin/env bash
# Graylog All-in-One Installer for Ubuntu Server 24.04
# Idempotent, fault-tolerant script to install and configure MongoDB, Graylog Data Node, and Graylog Server.
# Citations: See summary for key facts; full docs linked in comments.
# Usage: sudo ./install-graylog.sh [--auto-update]
# Auto-update: Fetches from https://raw.githubusercontent.com/your-repo/graylog-installer/main/install-graylog.sh (placeholder; replace with real URL).
# Checksum verification: Uses a hardcoded expected SHA256 (update manually).

set -euo pipefail
IFS=$'\n\t'

LOG="/var/log/graylog-install.log"
touch "$LOG" && chmod 600 "$LOG" && chown root:root "$LOG"
exec > >(tee -a "$LOG") 2>&1

AUTO_UPDATE=false
if [[ "${1:-}" == "--auto-update" ]]; then
  AUTO_UPDATE=true
fi

# Placeholder: Replace with your GitHub raw URL and expected SHA256 checksum.
SCRIPT_URL="https://raw.githubusercontent.com/your-repo/graylog-installer/main/install-graylog.sh"
EXPECTED_CHECKSUM="placeholder-sha256-replace-with-real-checksum-of-script"

require_root() {
  if [[ "$(id -u)" != 0 ]]; then
    echo "Must run as root (sudo)." >&2
    exit 1
  fi
}

apt_install_if_missing() {
  local pkgs=("$@")
  local to_install=()
  for pkg in "${pkgs[@]}"; do
    dpkg -s "$pkg" &>/dev/null || to_install+=("$pkg")
  done
  if [[ ${#to_install[@]} -gt 0 ]]; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${to_install[@]}"
  fi
}

auto_update() {
  if ! $AUTO_UPDATE; then return; fi
  echo "Auto-updating script..."
  TMP_SCRIPT="/tmp/updated-graylog-install.sh"
  curl -fsSL "$SCRIPT_URL" -o "$TMP_SCRIPT" || { echo "Failed to fetch updated script."; exit 1; }
  COMPUTED_SUM=$(sha256sum "$TMP_SCRIPT" | cut -d' ' -f1)
  if [[ "$COMPUTED_SUM" != "$EXPECTED_CHECKSUM" ]]; then
    echo "Checksum mismatch! Expected: $EXPECTED_CHECKSUM, Got: $COMPUTED_SUM"
    rm -f "$TMP_SCRIPT"
    exit 1
  fi
  chmod +x "$TMP_SCRIPT"
  exec "$TMP_SCRIPT" "$@"
}

backup_file() {
  local file="$1"
  if [[ -f "$file" ]]; then
    cp -p "$file" "${file}.bak.$(date +%s)"
    echo "Backed up $file"
  fi
}

config_set() {
  local file="$1" key="$2" value="$3"
  backup_file "$file"
  if grep -q "^${key}[[:space:]]*=" "$file"; then
    sed -i "s/^${key}[[:space:]]*=.*$/${key} = ${value}/" "$file"
  else
    echo "${key} = ${value}" >> "$file"
  fi
  echo "Set ${key} = ${value} in $file"
}

extract_conf_value() {
  local file="$1" key="$2"
  grep "^${key}[[:space:]]*=" "$file" | cut -d= -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

ensure_shared_password_secret() {
  local datanode_conf="/etc/graylog/datanode/datanode.conf"
  local server_conf="/etc/graylog/server/server.conf"
  mkdir -p "$(dirname "$datanode_conf")" "$(dirname "$server_conf")"
  touch "$datanode_conf" "$server_conf"
  local dn_secret server_secret
  dn_secret=$(extract_conf_value "$datanode_conf" "password_secret" || true)
  server_secret=$(extract_conf_value "$server_conf" "password_secret" || true)
  if [[ -n "$dn_secret" && -n "$server_secret" && "$dn_secret" == "$server_secret" ]]; then
    echo "Shared password_secret already set."
    return
  fi
  if [[ -z "$dn_secret" && -z "$server_secret" ]]; then
    local new_secret
    new_secret=$(openssl rand -hex 48)  # 96 chars for security (cite: Graylog docs require >=64)
    config_set "$datanode_conf" "password_secret" "$new_secret"
    config_set "$server_conf" "password_secret" "$new_secret"
    return
  fi
  # Sync if one exists
  local source_secret="${dn_secret:-$server_secret}"
  config_set "$datanode_conf" "password_secret" "$source_secret"
  config_set "$server_conf" "password_secret" "$source_secret"
  echo "Synced password_secret."
}

prompt_admin_password() {
  local pass1 pass2 sha
  while true; do
    read -s -p "Enter Graylog admin password: " pass1; echo
    read -s -p "Confirm: " pass2; echo
    [[ "$pass1" == "$pass2" && -n "$pass1" ]] && break
    echo "Mismatch or empty. Retry."
  done
  sha=$(echo -n "$pass1" | sha256sum | cut -d' ' -f1)
  echo "$sha"
}

ensure_root_sha2() {
  local server_conf="/etc/graylog/server/server.conf"
  if grep -q "^root_password_sha2[[:space:]]*=" "$server_conf"; then
    echo "root_password_sha2 already set."
    return
  fi
  local sha
  sha=$(prompt_admin_password)
  config_set "$server_conf" "root_password_sha2" "$sha"
}

set_mongo_bindipall() {
  local conf="/etc/mongod.conf"
  if ! [[ -f "$conf" ]]; then return; fi
  backup_file "$conf"
  if grep -q "bindIpAll: true" "$conf"; then
    echo "MongoDB bindIpAll already set."
    return
  fi
  # Safe YAML edit: Add under net if exists, else append.
  if grep -q "^net:" "$conf"; then
    sed -i '/^net:/a\  bindIpAll: true' "$conf"
  else
    echo -e "\nnet:\n  bindIpAll: true" >> "$conf"
  fi
  echo "Set MongoDB bindIpAll: true."
}

detect_heap_size() {
  local total_gb
  total_gb=$(free -g | awk '/^Mem:/{print $2}')
  if [[ $total_gb -lt 4 ]]; then
    echo "1g"  # Small for testing
  elif [[ $total_gb -lt 16 ]]; then
    echo "$((total_gb / 4))g"
  else
    echo "8g"  # Cap at 8g (cite: OpenSearch recommends 25-50% RAM, cap for stability)
  fi
}

set_jvm_heaps() {
  local datanode_conf="/etc/graylog/datanode/datanode.conf"
  local server_defaults="/etc/default/graylog-server"
  local heap
  heap=$(detect_heap_size)
  config_set "$datanode_conf" "opensearch_heap" "$heap"
  mkdir -p "$(dirname "$server_defaults")"
  local server_opts="-Xms${heap} -Xmx${heap} -server -XX:+UseG1GC -XX:-OmitStackTraceInFastThrow"
  if [[ -f "$server_defaults" ]] && grep -q "^GRAYLOG_SERVER_JAVA_OPTS=" "$server_defaults"; then
    sed -i "s/^GRAYLOG_SERVER_JAVA_OPTS=.*$/GRAYLOG_SERVER_JAVA_OPTS=\"$server_opts\"/" "$server_defaults"
  else
    echo "GRAYLOG_SERVER_JAVA_OPTS=\"$server_opts\"" >> "$server_defaults"
  fi
  echo "Set heaps to $heap based on ${total_gb}GB RAM."
}

ensure_datanode_configs() {
  local conf="/etc/graylog/datanode/datanode.conf"
  config_set "$conf" "opensearch_network_host" "0.0.0.0"  # Bind OpenSearch to all (cite: Graylog Data Node docs)
  config_set "$conf" "mongodb_uri" "mongodb://localhost:27017/graylog"
}

ensure_server_configs() {
  local conf="/etc/graylog/server/server.conf"
  local data_dir="/var/lib/graylog-server"
  mkdir -p "$data_dir"
  chown -R graylog:graylog "$data_dir" || true
  config_set "$conf" "data_dir" "$data_dir"
  config_set "$conf" "http_bind_address" "0.0.0.0:9000"
}

set_vm_max_map_count() {
  local sysctl_file="/etc/sysctl.d/99-graylog.conf"
  if sysctl vm.max_map_count | grep -q "262144"; then
    echo "vm.max_map_count already set."
    return
  fi
  echo "vm.max_map_count=262144" > "$sysctl_file"
  sysctl --load="$sysctl_file"
  echo "Set vm.max_map_count=262144."
}

start_and_wait() {
  local service="$1" max_attempts=15 sleep_sec=5
  systemctl daemon-reload
  systemctl enable "$service" --now || true
  for ((i=1; i<=max_attempts; i++)); do
    if systemctl is-active --quiet "$service"; then
      echo "$service started."
      return 0
    fi
    echo "Waiting for $service ($i/$max_attempts)..."
    sleep "$sleep_sec"
  done
  return 1
}

verify_service() {
  local service="$1" log_file="$2" port="$3" api_probe="$4"
  echo "Verifying $service:"
  # 1. systemd
  if ! systemctl is-active --quiet "$service"; then
    echo "FAIL: systemd not active."
    return 1
  fi
  systemctl status "$service" --no-pager -l
  # 2. Logs
  if journalctl -u "$service" -n 50 | grep -iq "error\|fatal"; then
    echo "FAIL: Errors in logs."
    journalctl -u "$service" -n 200 --no-pager
    return 1
  fi
  # 3. Network/API
  if ! ss -tuln | grep -q ":$port "; then
    echo "FAIL: Port $port not listening."
    return 1
  fi
  if [[ -n "$api_probe" ]]; then
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "$api_probe" || echo "fail")
    if [[ ! "$status" =~ ^(200|401)$ ]]; then
      echo "FAIL: API probe $api_probe returned $status."
      return 1
    fi
  fi
  echo "PASS: $service verified."
  return 0
}

handle_failure() {
  local component="$1" conf_file="$2" log_cmd="$3" restart_cmd="$4" extra="$5"
  echo "FAILURE in $component. Remediation:"
  echo "- Edit config: sudo sed -i 's/<bad_line>/<good_line>/' $conf_file  # Customize per issue"
  echo "- Tail logs: $log_cmd"
  echo "- Common errors: Check for OOM (increase heap), auth (check secrets), bind (check ports)."
  echo "- Restart: $restart_cmd"
  echo "- Verify ports: ss -tuln | grep <port>"
  echo "$extra"
  exit 1
}

main() {
  require_root
  auto_update "$@"
  echo "Starting Graylog installer."
  apt_install_if_missing gnupg curl wget apt-transport-https openssl ca-certificates jq

  # Java (cite: Graylog requires OpenJDK 17)
  apt_install_if_missing openjdk-17-jre-headless

  # MongoDB (cite: Official MongoDB 8.0 repo for Ubuntu 24.04)
  if ! dpkg -s mongodb-org &>/dev/null; then
    curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | gpg --dearmor -o /usr/share/keyrings/mongodb-server-8.0.gpg
    echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" > /etc/apt/sources.list.d/mongodb-org-8.0.list
    apt-get update -y
    apt-get install -y mongodb-org
    apt-mark hold mongodb-org
  fi
  set_mongo_bindipall
  if ! start_and_wait "mongod"; then
    handle_failure "MongoDB" "/etc/mongod.conf" "journalctl -u mongod -n 200" "sudo systemctl restart mongod" "sed -i '/^net:/a\  bindIpAll: true' /etc/mongod.conf"
  fi
  verify_service "mongod" "/var/log/mongodb/mongod.log" "27017" "" || handle_failure "MongoDB" ...

  # Graylog repo (cite: https://packages.graylog2.org)
  if ! dpkg -l | grep -q graylog-6.3-repository; then
    wget https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb -O /tmp/graylog-repo.deb
    dpkg -i /tmp/graylog-repo.deb
    apt-get update -y
  fi

  # Data Node
  apt_install_if_missing graylog-datanode
  set_vm_max_map_count
  ensure_datanode_configs
  ensure_shared_password_secret
  set_jvm_heaps
  if ! start_and_wait "graylog-datanode"; then
    handle_failure "Data Node" "/etc/graylog/datanode/datanode.conf" "journalctl -u graylog-datanode -n 200" "sudo systemctl restart graylog-datanode" "Check opensearch_heap or password_secret."
  fi
  verify_service "graylog-datanode" "/var/log/graylog-datanode/datanode.log" "9200" "http://127.0.0.1:9200/_cluster/health" || handle_failure "Data Node" ...
  verify_service "graylog-datanode" "/var/log/graylog-datanode/datanode.log" "8999" "" || handle_failure "Data Node REST" ...

  # Server
  apt_install_if_missing graylog-server
  ensure_shared_password_secret
  ensure_root_sha2
  ensure_server_configs
  if ! start_and_wait "graylog-server"; then
    handle_failure "Graylog Server" "/etc/graylog/server/server.conf" "journalctl -u graylog-server -n 200" "sudo systemctl restart graylog-server" "Check root_password_sha2 or http_bind_address."
  fi
  verify_service "graylog-server" "/var/log/graylog-server/server.log" "9000" "http://127.0.0.1:9000/api/system/cluster" || handle_failure "Graylog Server" ...

  echo "Installation complete. Access http://<ip>:9000 (admin/<your-pass>)."
  echo "To cleanup: source this script and call cleanup"
}

cleanup() {
  read -p "Confirm cleanup? (y/n): " confirm
  [[ "$confirm" != "y" ]] && return
  systemctl stop graylog-server graylog-datanode mongod || true
  apt-get purge -y graylog-server graylog-datanode mongodb-org openjdk-17-jre-headless
  rm -rf /etc/graylog /var/lib/graylog* /var/lib/mongodb /etc/mongod.conf* /etc/apt/sources.list.d/mongodb* /etc/apt/sources.list.d/graylog* /etc/default/graylog-server /etc/sysctl.d/99-graylog.conf
  systemctl daemon-reload
  echo "Cleanup complete."
}

main "$@"
