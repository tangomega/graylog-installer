#!/usr/bin/env bash
# installer.sh: Graylog All-in-One Installer for Ubuntu Server 24.04
# Idempotent, fault-tolerant script to install and configure MongoDB, Graylog Data Node, and Graylog Server.
# Citations: See https://go2docs.graylog.org/current/downloading_and_installing_graylog/ubuntu_installation.htm for Graylog setup,
# https://www.mongodb.org/docs/manual/tutorial/install-mongodb-on-ubuntu/ for MongoDB,
# https://opensearch.org/docs/latest/ for OpenSearch settings.
# Usage: sudo ./installer.sh
# On failure: Prompts to run cleanup function to reset the environment, including MongoDB.

set -euo pipefail
IFS=$'\n\t'

LOG="/var/log/graylog-install.log"
touch "$LOG" && chmod 600 "$LOG" && chown root:root "$LOG"
exec > >(tee -a "$LOG") 2>&1

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

backup_file() {
  local file="${1:-}"  # Handle empty input safely
  if [[ -n "$file" && -f "$file" ]]; then
    cp -p "$file" "${file}.bak.$(date +%s)"
    echo "Backed up $file"
  fi
}

config_set() {
  local file="${1:-}" key="${2:-}" value="${3:-}"
  if [[ -z "$file" || -z "$key" || -z "$value" ]]; then
    echo "config_set: Missing arguments" >&2
    return 1
  fi
  backup_file "$file"
  if grep -q "^${key}[[:space:]]*=" "$file"; then
    sed -i "s/^${key}[[:space:]]*=.*$/${key} = ${value}/" "$file"
  else
    echo "${key} = ${value}" >> "$file"
  fi
  echo "Set ${key} = ${value} in $file"
}

extract_conf_value() {
  local file="${1:-}" key="${2:-}"
  if [[ -f "$file" ]]; then
    grep "^${key}[[:space:]]*=" "$file" | cut -d= -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || true
  fi
}

ensure_shared_password_secret() {
  local datanode_conf="/etc/graylog/datanode/datanode.conf"
  local server_conf="/etc/graylog/server/server.conf"
  mkdir -p "$(dirname "$datanode_conf")" "$(dirname "$server_conf")"
  touch "$datanode_conf" "$server_conf"
  local dn_secret server_secret
  dn_secret=$(extract_conf_value "$datanode_conf" "password_secret")
  server_secret=$(extract_conf_value "$server_conf" "password_secret")
  if [[ -n "$dn_secret" && -n "$server_secret" && "$dn_secret" == "$server_secret" ]]; then
    echo "Shared password_secret already set."
    return
  fi
  if [[ -z "$dn_secret" && -z "$server_secret" ]]; then
    local new_secret
    new_secret=$(openssl rand -hex 48)  # 96 chars for security (cite: https://go2docs.graylog.org/current/setting_up_graylog/server.conf.html)
    config_set "$datanode_conf" "password_secret" "$new_secret"
    config_set "$server_conf" "password_secret" "$new_secret"
    return
  fi
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
  # Check if correctly configured
  if grep -q "^[[:space:]]*bindIpAll: true" "$conf" && ! grep -q "^[[:space:]]*bindIp:" "$conf" && ! grep -A1 "^net:" "$conf" | grep -q "^net:"; then
    echo "MongoDB bindIpAll already set correctly."
    return
  fi
  # Remove duplicate net: sections and bindIp entries
  sed -i '/^[[:space:]]*net:/,/^[[:space:]]*[a-zA-Z]/ { /^[[:space:]]*net:/d; /^[[:space:]]*bindIp:/d; /^[[:space:]]*bindIpAll:/d; }' "$conf"
  # Ensure single net: section with bindIpAll: true
  echo -e "\nnet:\n  bindIpAll: true" >> "$conf"
  # Validate config
  if ! mongod --config "$conf" --dryRun >/dev/null 2>&1; then
    echo "Invalid MongoDB config after modification."
    handle_failure "MongoDB Config Validation" "/etc/mongod.conf" "cat /etc/mongod.conf" "sudo systemctl restart mongod" "Restore backup: cp /etc/mongod.conf.bak.* /etc/mongod.conf"
  fi
  echo "Set MongoDB bindIpAll: true, removed bindIp and duplicates (cite: https://www.mongodb.org/docs/manual/tutorial/install-mongodb-on-ubuntu/)."
}

detect_heap_size() {
  local total_mb
  total_mb=$(free -m | awk '/^Mem:/{print $2}')
  if [[ $total_mb -lt 4096 ]]; then
    echo "1g"  # Small for testing
  elif [[ $total_mb -lt 16384 ]]; then
    echo "$((total_mb / 4096))g"
  else
    echo "8g"  # Cap at 8g (cite: https://opensearch.org/docs/latest/ for heap recommendations)
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
  echo "Set heaps to $heap based on ${total_mb:-unknown}MB RAM."
}

ensure_datanode_configs() {
  local conf="/etc/graylog/datanode/datanode.conf"
  config_set "$conf" "opensearch_network_host" "0.0.0.0"  # Bind OpenSearch to all (cite: https://go2docs.graylog.org/current/setting_up_graylog/data_node_configuration_file.htm)
  config_set "$conf" "mongodb_uri" "mongodb://localhost:27017/graylog"
}

ensure_server_configs() {
  local conf="/etc/graylog/server/server.conf"
  local data_dir="/var/lib/graylog-server"
  mkdir -p "$data_dir" /var/lib/graylog-datanode /var/lib/mongodb
  chown -R graylog:graylog "$data_dir" /var/lib/graylog-datanode || true
  chown -R mongodb:mongodb /var/lib/mongodb || true
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
  echo "Set vm.max_map_count=262144 (cite: https://opensearch.org/docs/latest/)."
}

start_and_wait() {
  local service="${1:-}"
  local max_attempts=15 sleep_sec=5
  if [[ -z "$service" ]]; then
    echo "start_and_wait: Missing service name" >&2
    return 1
  fi
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
  local service="${1:-}" log_file="${2:-}" port="${3:-}" api_probe="${4:-}"
  if [[ -z "$service" ]]; then
    echo "verify_service: Missing service name" >&2
    return 1
  fi
  echo "Verifying $service:"
  if ! systemctl is-active --quiet "$service"; then
    echo "FAIL: systemd not active."
    return 1
  fi
  systemctl status "$service" --no-pager -l
  # Get service start time to filter logs
  local start_time
  start_time=$(systemctl show "$service" --property=ActiveEnterTimestamp | cut -d= -f2)
  if [[ -n "$log_file" && -f "$log_file" && -n "$start_time" ]] && journalctl -u "$service" --since "$start_time" -n 50 | grep -iq "error\|fatal"; then
    echo "FAIL: Errors in logs since $start_time."
    journalctl -u "$service" --since "$start_time" -n 200 --no-pager
    return 1
  fi
  if [[ -n "$port" ]] && ! ss -tuln | grep -q ":$port "; then
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

prompt_cleanup() {
  read -p "Installation failed. Run cleanup to reset environment? (y/n): " confirm
  if [[ "$confirm" == "y" ]]; then
    cleanup
    echo "Environment reset. Re-run the script to try again."
  else
    echo "Skipping cleanup. Manual remediation required."
  fi
}

handle_failure() {
  local component="${1:-Unknown}" conf_file="${2:-}" log_cmd="${3:-}" restart_cmd="${4:-}" extra="${5:-}"
  echo "FAILURE in $component. Remediation:"
  if [[ -n "$conf_file" ]]; then
    echo "- Edit config: sudo nano $conf_file # Check for syntax errors or missing keys"
  fi
  if [[ -n "$log_cmd" ]]; then
    echo "- Tail logs: $log_cmd"
  fi
  echo "- Common errors: Check for OOM (increase heap in /etc/default/graylog-server or /etc/graylog/datanode/datanode.conf), auth (verify password_secret), bind (ss -tuln | grep <port>)."
  if [[ -n "$restart_cmd" ]]; then
    echo "- Restart: $restart_cmd"
  fi
  if [[ -n "$extra" ]]; then
    echo "- Additional: $extra"
  fi
  prompt_cleanup
  exit 1
}

cleanup() {
  read -p "Confirm cleanup? (y/n): " confirm
  if [[ "$confirm" != "y" ]]; then return; fi
  systemctl stop graylog-server graylog-datanode mongod || true
  apt-get purge -y graylog-server graylog-datanode mongodb-org openjdk-17-jre-headless
  rm -rf /etc/graylog /var/lib/graylog* /var/lib/mongodb /var/log/mongodb /etc/mongod.conf* /etc/apt/sources.list.d/mongodb* /etc/apt/sources.list.d/graylog* /etc/default/graylog-server /etc/sysctl.d/99-graylog.conf
  systemctl daemon-reload
  echo "Cleanup complete."
}

main() {
  require_root
  echo "Starting Graylog installer."
  apt_install_if_missing gnupg curl wget apt-transport-https openssl ca-certificates jq

  # Java (cite: https://go2docs.graylog.org/current/downloading_and_installing_graylog/ubuntu_installation.htm requires OpenJDK 17)
  apt_install_if_missing openjdk-17-jre-headless

  # MongoDB (cite: https://www.mongodb.org/docs/manual/tutorial/install-mongodb-on-ubuntu/)
  if ! dpkg -s mongodb-org &>/dev/null; then
    curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | gpg --dearmor -o /usr/share/keyrings/mongodb-server Cristián Ramírez Rodríguez (CRo) -8.0.gpg
    echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" > /etc/apt/sources.list.d/mongodb-org-8.0.list
    apt-get update -y
    apt-get install -y mongodb-org
    apt-mark hold mongodb-org
  fi
  set_mongo_bindipall
  if ! start_and_wait "mongod"; then
    handle_failure "MongoDB" "/etc/mongod.conf" "journalctl -u mongod -n 200" "sudo systemctl restart mongod" "sed -i '/^[[:space:]]*bindIp:/d' /etc/mongod.conf; sed -i '/^[[:space:]]*net:/,/^[[:space:]]*[a-zA-Z]/d; $ a\nnet:\n  bindIpAll: true' /etc/mongod.conf"
  fi
  verify_service "mongod" "/var/log/mongodb/mongod.log" "27017" "" || handle_failure "MongoDB" "/etc/mongod.conf" "journalctl -u mongod -n 200" "sudo systemctl restart mongod" ""

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
  verify_service "graylog-datanode" "/var/log/graylog-datanode/datanode.log" "9200" "http://127.0.0.1:9200/_cluster/health" || handle_failure "Data Node" "/etc/graylog/datanode/datanode.conf" "journalctl -u graylog-datanode -n 200" "sudo systemctl restart graylog-datanode" ""
  verify_service "graylog-datanode" "/var/log/graylog-datanode/datanode.log" "8999" "" || handle_failure "Data Node REST" "/etc/graylog/datanode/datanode.conf" "journalctl -u graylog-datanode -n 200" "sudo systemctl restart graylog-datanode" ""

  # Server
  apt_install_if_missing graylog-server
  ensure_shared_password_secret
  ensure_root_sha2
  ensure_server_configs
  if ! start_and_wait "graylog-server"; then
    handle_failure "Graylog Server" "/etc/graylog/server/server.conf" "journalctl -u graylog-server -n 200" "sudo systemctl restart graylog-server" "Check root_password_sha2 or http_bind_address."
  fi
  verify_service "graylog-server" "/var/log/graylog-server/server.log" "9000" "http://127.0.0.1:9000/api/system/cluster" || handle_failure "Graylog Server" "/etc/graylog/server/server.conf" "journalctl -u graylog-server -n 200" "sudo systemctl restart graylog-server" ""

  echo "Installation complete. Access http://<ip>:9000 (admin/<your-pass>)."
  echo "To cleanup: source this script and call cleanup"
}

main "$@"
