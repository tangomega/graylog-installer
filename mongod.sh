#!/usr/bin/env bash
# mongod.sh: MongoDB Installer for Ubuntu Server 24.04
# Idempotent, fault-tolerant script to install and configure MongoDB 8.0 with net: { port: 27017, bindIpAll: true }.
# Supports auto-update with Git SSH key authentication.
# Citation: https://www.mongodb.org/docs/manual/tutorial/install-mongodb-on-ubuntu/ for MongoDB setup.
# Usage: sudo ./mongod.sh [--update]
# On failure: Prompts to run cleanup function to reset MongoDB environment.
# Fails only if mongod is not running or port 27017 is not listening.

set -euo pipefail
IFS=$'\n\t'

# Auto-update configuration (replace with your values)
SCRIPT_URL="https://raw.githubusercontent.com/<user>/<repo>/main/mongod.sh"  # Replace with your GitHub raw URL
EXPECTED_CHECKSUM="replace_with_actual_sha256_checksum"  # Replace with: sha256sum mongod.sh
GIT_SSH_KEY="/root/.ssh/id_rsa"  # Replace with path to your SSH key if different

LOG="/var/log/mongodb-install.log"
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
  local file="${1:-}"
  if [[ -n "$file" && -f "$file" ]]; then
    cp -p "$file" "${file}.bak.$(date +%s)"
    echo "Backed up $file"
  fi
}

auto_update() {
  apt_install_if_missing openssh-client
  if [[ ! -f "$GIT_SSH_KEY" ]]; then
    echo "Git SSH key not found at $GIT_SSH_KEY. Skipping update." >&2
    return 1
  fi
  chmod 600 "$GIT_SSH_KEY"
  mkdir -p ~/.ssh
  cat > ~/.ssh/config <<EOF
Host github.com
  HostName github.com
  User git
  IdentityFile $GIT_SSH_KEY
  IdentitiesOnly yes
EOF
  chmod 600 ~/.ssh/config
  ssh-keyscan -H github.com >> ~/.ssh/known_hosts 2>/dev/null
  local tmp_script="/tmp/mongod.sh.new"
  if ! curl -fsSL --connect-timeout 5 "$SCRIPT_URL" -o "$tmp_script"; then
    echo "Failed to download updated script. Continuing with current version." >&2
    return 1
  fi
  local checksum
  checksum=$(sha256sum "$tmp_script" | cut -d' ' -f1)
  if [[ "$checksum" != "$EXPECTED_CHECKSUM" ]]; then
    echo "Checksum mismatch (got $checksum, expected $EXPECTED_CHECKSUM). Aborting update." >&2
    rm -f "$tmp_script"
    return 1
  fi
  chmod +x "$tmp_script"
  mv "$tmp_script" "$0"
  echo "Script updated successfully. Re-running..."
  exec "$0" "$@"
}

set_mongo_bindipall() {
  local conf="/etc/mongod.conf"
  if ! [[ -f "$conf" ]]; then return; fi
  backup_file "$conf"
  # Check if correctly configured (net: { port: 27017, bindIpAll: true } present, no bindIp)
  if grep -A2 "^[[:space:]]*net:" "$conf" | grep -q "port: 27017" && grep -A2 "^[[:space:]]*net:" "$conf" | grep -q "bindIpAll: true" && ! grep -q "^[[:space:]]*bindIp:" "$conf"; then
    echo "MongoDB net: { port: 27017, bindIpAll: true } already set correctly."
    return
  fi
  # Remove any existing net: sections and standalone bindIp/port entries
  sed -i '/^[[:space:]]*net:/,/^[[:space:]]*[a-zA-Z#]/d' "$conf"
  sed -i '/^[[:space:]]*bindIp:/d' "$conf"
  sed -i '/^[[:space:]]*port:/d' "$conf"
  # Append new net: section after # network interfaces
  sed -i '/^[[:space:]]*# network interfaces/a\nnet:\n  port: 27017\n  bindIpAll: true' "$conf"
  # Validate config
  if ! mongod --config "$conf" --dryRun >/dev/null 2>&1; then
    echo "Invalid MongoDB config after modification."
    handle_failure "MongoDB Config Validation" "/etc/mongod.conf" "cat /etc/mongod.conf" "sudo systemctl restart mongod" "Restore backup: cp /etc/mongod.conf.bak.* /etc/mongod.conf"
  fi
  echo "Set MongoDB net: { port: 27017, bindIpAll: true }, removed bindIp and duplicate net: sections (cite: https://www.mongodb.org/docs/manual/tutorial/install-mongodb-on-ubuntu/)."
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
  local service="${1:-}" log_file="${2:-}" port="${3:-}"
  if [[ -z "$service" ]]; then
    echo "verify_service: Missing service name" >&2
    return 1
  fi
  echo "Verifying $service:"
  # Check systemd state
  if ! systemctl is-active --quiet "$service"; then
    echo "FAIL: systemd not active."
    return 1
  fi
  systemctl status "$service" --no-pager -l
  # Check port
  if [[ -n "$port" ]] && ! ss -tuln | grep -q ":$port "; then
    echo "FAIL: Port $port not listening."
    return 1
  fi
  # Check logs since last start (informational, not failing)
  local start_time
  start_time=$(systemctl show "$service" --property=ActiveEnterTimestamp | cut -d= -f2)
  if [[ -n "$log_file" && -f "$log_file" && -n "$start_time" ]] && journalctl -u "$service" --since "$start_time" -n 50 | grep -iq "error\|fatal"; then
    echo "WARNING: Errors in logs since $start_time (not failing as per requirement)."
    journalctl -u "$service" --since "$start_time" -n 200 --no-pager
  fi
  echo "PASS: $service verified."
  return 0
}

prompt_cleanup() {
  read -p "Installation failed. Run cleanup to reset MongoDB environment? (y/n): " confirm
  if [[ "$confirm" == "y" ]]; then
    cleanup
    echo "MongoDB environment reset. Re-run the script to try again."
  else
    echo "Skipping cleanup. Manual remediation required."
  fi
}

handle_failure() {
  local component="${1:-Unknown}" conf_file="${2:-}" log_cmd="${3:-}" restart_cmd="${4:-}" extra="${5:-}"
  echo "FAILURE in $component. Remediation:"
  if [[ -n "$conf_file" ]]; then
    echo "- Edit config: sudo nano $conf_file # Check for syntax errors or duplicate keys"
  fi
  if [[ -n "$log_cmd" ]]; then
    echo "- Tail logs: $log_cmd"
  fi
  echo "- Common errors: Check for YAML errors (duplicate keys in /etc/mongod.conf), bind issues (ss -tuln | grep 27017)."
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
  systemctl stop mongod || true
  apt-get purge -y mongodb-org
  rm -rf /var/lib/mongodb /var/log/mongodb /etc/mongod.conf* /etc/apt/sources.list.d/mongodb*
  systemctl daemon-reload
  echo "MongoDB cleanup complete."
}

main() {
  require_root
  if [[ "${1:-}" == "--update" ]]; then
    echo "Checking for script updates..."
    auto_update "$@"
  fi
  echo "Starting MongoDB installer."
  apt_install_if_missing gnupg curl wget apt-transport-https

  # MongoDB (cite: https://www.mongodb.org/docs/manual/tutorial/install-mongodb-on-ubuntu/)
  if ! dpkg -s mongodb-org &>/dev/null; then
    curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | gpg --dearmor -o /usr/share/keyrings/mongodb-server-8.0.gpg
    echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" > /etc/apt/sources.list.d/mongodb-org-8.0.list
    apt-get update -y
    apt-get install -y mongodb-org
    apt-mark hold mongodb-org
  fi
  set_mongo_bindipall
  if ! start_and_wait "mongod"; then
    handle_failure "MongoDB" "/etc/mongod.conf" "journalctl -u mongod -n 200" "sudo systemctl restart mongod" "sed -i '/^[[:space:]]*net:/,/^[[:space:]]*[a-zA-Z#]/d; /^[[:space:]]*bindIp:/d; /^[[:space:]]*port:/d; /^[[:space:]]*# network interfaces/a\\net:\\n  port: 27017\\n  bindIpAll: true' /etc/mongod.conf"
  fi
  verify_service "mongod" "/var/log/mongodb/mongod.log" "27017" || handle_failure "MongoDB" "/etc/mongod.conf" "journalctl -u mongod -n 200" "sudo systemctl restart mongod" ""

  echo "MongoDB installation complete. mongod is running on port 27017."
  echo "To cleanup: source this script and call cleanup"
}

main "$@"
