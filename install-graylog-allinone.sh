#!/usr/bin/env bash
# install-graylog-allinone-robust.sh
# Robust, idempotent Graylog all-in-one installer for Ubuntu 24.04
# - Installs MongoDB 8.0, Graylog Data Node (OpenSearch), Graylog server
# - Ensures mongodb bindIpAll: true
# - Ensures shared password_secret between datanode and server
# - Ensures root_password_sha2 exists (prompts if missing)
# - 3-level verification for each service (systemd, process/log, port/API)
# - Safe re-runnable, config backups, logging, retries
#
# Run as root or via sudo:
# sudo ./install-graylog-allinone-robust.sh

set -euo pipefail
IFS=$'\n\t'

### Configuration
LOGFILE="/var/log/graylog-installer.log"
TIMESTAMP="$(date -u +'%Y%m%dT%H%M%SZ')"
BACKUP_DIR="/etc/graylog/backup-${TIMESTAMP}"
MONGO_CONF="/etc/mongod.conf"
DATANODE_CONF="/etc/graylog/datanode/datanode.conf"
SERVER_CONF="/etc/graylog/server/server.conf"
GD_REPO_DEB_URL="https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb"
MONGO_GPG_URL="https://www.mongodb.org/static/pgp/server-8.0.asc"
MONGO_APT_LIST="/etc/apt/sources.list.d/mongodb-org-8.0.list"

# Timeouts / retries
START_RETRY=6
START_WAIT=5

# Helpers
log() {
  echo "[$(date '+%F %T')] $*" | tee -a "$LOGFILE"
}
die() {
  echo >&2
  log "ERROR: $*"
  echo "----- Last 40 lines of Graylog server log -----" | tee -a "$LOGFILE"
  sudo tail -n 40 /var/log/graylog-server/server.log 2>/dev/null || true
  echo "----- Last 40 lines of Data Node log -----" | tee -a "$LOGFILE"
  sudo tail -n 40 /var/log/graylog-datanode/datanode.log 2>/dev/null || true
  echo "----- Last 200 lines of MongoDB log -----" | tee -a "$LOGFILE"
  sudo tail -n 200 /var/log/mongodb/mongod.log 2>/dev/null || true
  exit 1
}
ensure_sudo() {
  if [ "$EUID" -ne 0 ]; then
    die "This script must be run as root (use sudo)."
  fi
}

backup_configs() {
  log "Backing up critical config files to $BACKUP_DIR"
  sudo mkdir -p "$BACKUP_DIR"
  for f in "$MONGO_CONF" "$DATANODE_CONF" "$SERVER_CONF" /etc/default/graylog-server /etc/sysctl.d/99-graylog-datanode.conf; do
    if [ -f "$f" ]; then
      sudo cp -av "$f" "$BACKUP_DIR/" | tee -a "$LOGFILE"
    fi
  done
}

apt_install_if_missing() {
  local pkgs=("$@")
  local to_install=()
  for p in "${pkgs[@]}"; do
    if ! dpkg -s "$p" >/dev/null 2>&1; then
      to_install+=("$p")
    fi
  done
  if [ "${#to_install[@]}" -gt 0 ]; then
    log "Installing packages: ${to_install[*]}"
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${to_install[@]}"
  else
    log "All required packages already installed: ${pkgs[*]}"
  fi
}

# Robustly set bindIpAll: true in /etc/mongod.conf
set_mongo_bindipall() {
  log "Ensuring MongoDB binds to all interfaces (bindIpAll: true)"
  sudo cp -av "$MONGO_CONF" "${MONGO_CONF}.orig" >>"$LOGFILE" 2>&1 || true

  # If bindIpAll already present, set to true
  if sudo grep -qE '^\s*bindIpAll\s*:\s*true' "$MONGO_CONF"; then
    log "bindIpAll: true already set"
    return
  fi

  # If bindIp: exists, replace it with bindIpAll: true preserving indentation
  if sudo grep -qE '^\s*bindIp\s*:' "$MONGO_CONF"; then
    log "Replacing existing bindIp line with bindIpAll: true"
    sudo sed -i -E 's/^(\s*)bindIp\s*:.*/\1bindIpAll: true/' "$MONGO_CONF"
    return
  fi

  # If net: section exists but no bind lines, insert bindIpAll under net:
  if sudo grep -qE '^\s*net\s*:' "$MONGO_CONF"; then
    log "Inserting bindIpAll: true under existing net: section"
    # Insert after the net: line (the first matching net:)
    sudo awk '
      BEGIN { inserted=0 }
      { print $0 }
      /^\s*net\s*:/ && !inserted {
        getline; print $0
        print "  bindIpAll: true"
        inserted=1
        next
      }
    ' "$MONGO_CONF" | sudo tee "${MONGO_CONF}.tmp" >/dev/null
    # Fallback: if tmp exists, move
    if [ -f "${MONGO_CONF}.tmp" ]; then
      sudo mv "${MONGO_CONF}.tmp" "$MONGO_CONF"
    fi
    return
  fi

  # Otherwise append a net: block at EOF
  log "Appending net: bindIpAll: true to end of $MONGO_CONF"
  printf "\n# Added by graylog installer\nnet:\n  bindIpAll: true\n" | sudo tee -a "$MONGO_CONF" >/dev/null
}

# Set or ensure shared password_secret
ensure_password_secret() {
  local dn_secret=""
  local serv_secret=""
  if [ -f "$DATANODE_CONF" ]; then
    dn_secret=$(awk -F'=' '/^password_secret[[:space:]]*=/ { gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit }' "$DATANODE_CONF" || true)
  fi
  if [ -f "$SERVER_CONF" ]; then
    serv_secret=$(awk -F'=' '/^password_secret[[:space:]]*=/ { gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit }' "$SERVER_CONF" || true)
  fi

  if [ -n "$dn_secret" ] && [ -n "$serv_secret" ]; then
    if [ "$dn_secret" != "$serv_secret" ]; then
      log "Warning: DataNode and Server have different password_secret values. Overwriting server with datanode secret."
      sudo cp -av "$SERVER_CONF" "${SERVER_CONF}.prepass" >>"$LOGFILE" 2>&1 || true
      sudo sed -i "s|^password_secret[[:space:]]*=.*|password_secret = $dn_secret|" "$SERVER_CONF"
      PASS_SECRET="$dn_secret"
    else
      PASS_SECRET="$dn_secret"
      log "Found existing identical password_secret; reusing it"
    fi
  elif [ -n "$dn_secret" ] && [ -z "$serv_secret" ]; then
    PASS_SECRET="$dn_secret"
    log "Copying datanode password_secret into server.conf"
    sudo cp -av "$SERVER_CONF" "${SERVER_CONF}.prepass" >>"$LOGFILE" 2>&1 || true
    if sudo grep -q '^password_secret' "$SERVER_CONF"; then
      sudo sed -i "s|^password_secret[[:space:]]*=.*|password_secret = $PASS_SECRET|" "$SERVER_CONF"
    else
      echo "password_secret = $PASS_SECRET" | sudo tee -a "$SERVER_CONF" >/dev/null
    fi
  elif [ -z "$dn_secret" ] && [ -n "$serv_secret" ]; then
    PASS_SECRET="$serv_secret"
    log "Copying server password_secret into datanode.conf"
    sudo cp -av "$DATANODE_CONF" "${DATANODE_CONF}.prepass" >>"$LOGFILE" 2>&1 || true
    if sudo grep -q '^password_secret' "$DATANODE_CONF"; then
      sudo sed -i "s|^password_secret[[:space:]]*=.*|password_secret = $PASS_SECRET|" "$DATANODE_CONF"
    else
      echo "password_secret = $PASS_SECRET" | sudo tee -a "$DATANODE_CONF" >/dev/null
    fi
  else
    log "No password_secret found. Generating a new one."
    PASS_SECRET=$(openssl rand -hex 32)
    log "Generated password_secret: $PASS_SECRET"
    sudo mkdir -p "$(dirname "$DATANODE_CONF")"
    sudo mkdir -p "$(dirname "$SERVER_CONF")"
    # Ensure setting in datanode
    if sudo grep -q '^password_secret' "$DATANODE_CONF" 2>/dev/null; then
      sudo sed -i "s|^password_secret[[:space:]]*=.*|password_secret = $PASS_SECRET|" "$DATANODE_CONF"
    else
      echo "password_secret = $PASS_SECRET" | sudo tee -a "$DATANODE_CONF" >/dev/null
    fi
    # Ensure setting in server
    if sudo grep -q '^password_secret' "$SERVER_CONF" 2>/dev/null; then
      sudo sed -i "s|^password_secret[[:space:]]*=.*|password_secret = $PASS_SECRET|" "$SERVER_CONF"
    else
      echo "password_secret = $PASS_SECRET" | sudo tee -a "$SERVER_CONF" >/dev/null
    fi
  fi
  log "password_secret in use: ${PASS_SECRET:0:8}... (trimmed)"
}

# Ensure root_password_sha2 exists; prompt only if missing
ensure_root_sha2() {
  local cur_sha2=""
  if [ -f "$SERVER_CONF" ]; then
    cur_sha2=$(awk -F'=' '/^root_password_sha2[[:space:]]*=/ { gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit }' "$SERVER_CONF" || true)
  fi
  if [ -n "$cur_sha2" ]; then
    ROOT_PASS_SHA2="$cur_sha2"
    log "Existing root_password_sha2 found in server.conf; preserving it."
    return
  fi

  # Prompt for admin password once (silent) and store hash
  log "No root_password_sha2 found. Prompting for Graylog admin password (will not echo)."
  while true; do
    read -s -p "Enter Graylog admin password: " GL_PASS1
    echo
    read -s -p "Confirm Graylog admin password: " GL_PASS2
    echo
    if [ "$GL_PASS1" != "$GL_PASS2" ]; then
      echo "Passwords do not match. Please try again."
    elif [ -z "$GL_PASS1" ]; then
      echo "Password cannot be empty. Please try again."
    else
      break
    fi
  done
  ROOT_PASS_SHA2=$(echo -n "$GL_PASS1" | sha256sum | cut -d' ' -f1)
  # write to server.conf safely
  sudo cp -av "$SERVER_CONF" "${SERVER_CONF}.preroot" >>"$LOGFILE" 2>&1 || true
  if sudo grep -q '^root_password_sha2' "$SERVER_CONF" 2>/dev/null; then
    sudo sed -i "s|^root_password_sha2[[:space:]]*=.*|root_password_sha2 = $ROOT_PASS_SHA2|" "$SERVER_CONF"
  else
    echo "root_password_sha2 = $ROOT_PASS_SHA2" | sudo tee -a "$SERVER_CONF" >/dev/null
  fi
  log "root_password_sha2 written to server.conf (hash only shown in logfile)"
}

# Safe insertion/replacement helpers for server.conf settings
ensure_server_http_bind() {
  if sudo grep -qE '^\s*http_bind_address\s*=' "$SERVER_CONF"; then
    sudo sed -i 's|^\s*#\?\s*http_bind_address\s*=.*|http_bind_address = 0.0.0.0:9000|' "$SERVER_CONF"
  else
    echo "http_bind_address = 0.0.0.0:9000" | sudo tee -a "$SERVER_CONF" >/dev/null
  fi
}

# Ensure Graylog Java opts
ensure_graylog_java_opts() {
  local opts='GRAYLOG_SERVER_JAVA_OPTS="-Xms2g -Xmx2g -server -XX:+UseG1GC -XX:-OmitStackTraceInFastThrow"'
  if [ -f /etc/default/graylog-server ]; then
    if sudo grep -q '^GRAYLOG_SERVER_JAVA_OPTS' /etc/default/graylog-server; then
      sudo sed -i "s|^GRAYLOG_SERVER_JAVA_OPTS=.*|$opts|" /etc/default/graylog-server
    else
      echo "$opts" | sudo tee -a /etc/default/graylog-server >/dev/null
    fi
  else
    echo "$opts" | sudo tee /etc/default/graylog-server >/dev/null
  fi
}

# Start and ensure a systemd service with retries
start_and_wait() {
  local svc="$1"
  log "Enabling and starting service $svc"
  sudo systemctl enable "$svc" --now
  local i=0
  while [ $i -lt $START_RETRY ]; do
    if systemctl is-active --quiet "$svc"; then
      log "Service $svc is active."
      return 0
    fi
    i=$((i+1))
    log "Waiting for $svc to become active... (attempt $i/$START_RETRY)"
    sleep "$START_WAIT"
  done
  log "Service $svc did not become active within expected time."
  return 1
}

# 3-level health checks for each service
check_mongodb() {
  log "==== MongoDB checks ===="
  sudo systemctl status mongod --no-pager | sed -n '1,120p' | tee -a "$LOGFILE"
  log "Process check:"
  ps aux | grep '[m]ongod' | tee -a "$LOGFILE" || true

  # Port listening
  if ss -tulpen | grep -q ':27017'; then
    log "MongoDB is listening on port 27017"
  else
    die "MongoDB is not listening on port 27017"
  fi

  # Try a basic mongo command for status
  if command -v mongosh >/dev/null 2>&1; then
    if mongosh --eval "db.adminCommand('ping')" >/dev/null 2>&1; then
      log "MongoDB ping succeeded (mongosh)"
    else
      die "MongoDB ping failed"
    fi
  else
    # fallback to checking log for startup
    if sudo tail -n 50 /var/log/mongodb/mongod.log | grep -iE 'waiting for connections|waiting for connections on port' >/dev/null 2>&1; then
      log "MongoDB log indicates it is waiting for connections"
    else
      die "Unable to confirm MongoDB readiness (mongosh not present and logs inconclusive)"
    fi
  fi
}

check_datanode() {
  log "==== Graylog Data Node (OpenSearch) checks ===="
  sudo systemctl status graylog-datanode --no-pager | sed -n '1,120p' | tee -a "$LOGFILE"
  log "Process check:"
  ps aux | grep '[o]pensearch' | tee -a "$LOGFILE" || ps aux | grep '[g]raylog-datanode' | tee -a "$LOGFILE" || true

  # Log check
  if [ -f /var/log/graylog-datanode/datanode.log ]; then
    sudo tail -n 30 /var/log/graylog-datanode/datanode.log | tee -a "$LOGFILE"
    if sudo tail -n 50 /var/log/graylog-datanode/datanode.log | grep -i 'error' >/dev/null 2>&1; then
      log "Data Node log contains 'error' lines (inspect datanode.log)"
    fi
  fi

  # HTTP API check with retries
  local i=0
  while [ $i -lt $START_RETRY ]; do
    if curl -sS --max-time 3 http://127.0.0.1:9200/_cluster/health | grep -q '"status"'; then
      log "OpenSearch HTTP API responded"
      return 0
    fi
    log "Waiting for OpenSearch HTTP API... (attempt $((i+1))/$START_RETRY)"
    i=$((i+1)); sleep "$START_WAIT"
  done
  die "OpenSearch HTTP API not responding on http://127.0.0.1:9200"
}

check_graylog_server() {
  log "==== Graylog Server checks ===="
  sudo systemctl status graylog-server --no-pager | sed -n '1,120p' | tee -a "$LOGFILE"
  log "Process/log check:"
  ps aux | grep '[g]raylog.server' | tee -a "$LOGFILE" || ps aux | grep '[g]raylog-server' | tee -a "$LOGFILE" || true
  if [ -f /var/log/graylog-server/server.log ]; then
    sudo tail -n 30 /var/log/graylog-server/server.log | tee -a "$LOGFILE"
    if sudo tail -n 50 /var/log/graylog-server/server.log | grep -i 'error' >/dev/null 2>&1; then
      log "Graylog server log contains 'error' lines (inspect server.log)"
    fi
  fi

  # HTTP API check: requires admin credentials
  if [ -z "${ROOT_PASS_SHA2:-}" ]; then
    die "Missing ROOT_PASS_SHA2 for Graylog API check"
  fi
  # We can't reverse the hash; assume admin user exists. We'll attempt a basic request to /api/system/cluster using admin credentials
  # If local GL_PASS not available, attempt a 401 check as a fallback (reachable endpoint)
  local i=0
  while [ $i -lt $START_RETRY ]; do
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://127.0.0.1:9000/api/system/cluster || true)
    if [ "$code" = "200" ]; then
      log "Graylog API returned 200 OK"
      return 0
    elif [ "$code" = "401" ] || [ "$code" = "403" ]; then
      log "Graylog API reachable (http status $code) — credentials required but endpoint is up"
      return 0
    fi
    log "Waiting for Graylog API to become reachable... (attempt $((i+1))/$START_RETRY)"
    i=$((i+1)); sleep "$START_WAIT"
  done
  die "Graylog web/API on http://127.0.0.1:9000 not reachable"
}

# Main flow
main() {
  ensure_sudo
  log "===== Starting Graylog all-in-one robust installer ====="

  # Create log and backup
  sudo mkdir -p "$(dirname "$LOGFILE")"
  touch "$LOGFILE"
  backup_configs

  # Install prerequisites
  apt_install_if_missing gnupg curl wget apt-transport-https openssl ca-certificates

  # Install Java 17 if missing
  apt_install_if_missing openjdk-17-jre-headless

  # Install MongoDB repo and package if missing
  if ! dpkg -s mongodb-org >/dev/null 2>&1; then
    log "Adding MongoDB 8.0 repository and installing mongodb-org"
    curl -fsSL "$MONGO_GPG_URL" | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor
    echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" | sudo tee "$MONGO_APT_LIST" >/dev/null
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y mongodb-org
    sudo apt-mark hold mongodb-org || true
  else
    log "mongodb-org already installed"
  fi

  # Ensure mongodb bindIpAll
  set_mongo_bindipall

  # Start mongodb
  if ! start_and_wait mongod.service; then
    sudo journalctl -u mongod -n 200 --no-pager | sed -n '1,200p' | tee -a "$LOGFILE"
    die "Failed to start mongod.service"
  fi

  # Install Graylog repository package if not present
  if ! dpkg -l | grep -q graylog; then
    log "Installing Graylog repository package"
    wget -q "$GD_REPO_DEB_URL" -O /tmp/graylog-repo.deb
    sudo dpkg -i /tmp/graylog-repo.deb || true
    apt-get update -y
  else
    log "Graylog repo package appears installed"
  fi

  # Install datanode if missing
  if ! dpkg -s graylog-datanode >/dev/null 2>&1; then
    log "Installing graylog-datanode"
    DEBIAN_FRONTEND=noninteractive apt-get install -y graylog-datanode
  else
    log "graylog-datanode already installed"
  fi

  # Ensure vm.max_map_count
  sudo sysctl -w vm.max_map_count=262144 || true
  echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-graylog-datanode.conf >/dev/null
  sudo sysctl --system >/dev/null || true

  # Ensure datanode conf exists
  sudo mkdir -p "$(dirname "$DATANODE_CONF")"
  if [ ! -f "$DATANODE_CONF" ]; then
    echo "# created by installer" | sudo tee "$DATANODE_CONF" >/dev/null
  fi

  # Ensure server conf exists
  sudo mkdir -p "$(dirname "$SERVER_CONF")"
  if [ ! -f "$SERVER_CONF" ]; then
    echo "# created by installer" | sudo tee "$SERVER_CONF" >/dev/null
  fi

  # Ensure shared password_secret between datanode and server
  ensure_password_secret

  # Ensure root password sha2 is present (prompt only if missing)
  ensure_root_sha2

  # Ensure http bind and Java opts in server config
  ensure_server_http_bind
  ensure_graylog_java_opts

  # Start datanode
  if ! start_and_wait graylog-datanode.service; then
    sudo journalctl -u graylog-datanode -n 200 --no-pager | sed -n '1,200p' | tee -a "$LOGFILE"
    die "Failed to start graylog-datanode.service"
  fi

  # Install graylog-server if needed
  if ! dpkg -s graylog-server >/dev/null 2>&1; then
    log "Installing graylog-server"
    DEBIAN_FRONTEND=noninteractive apt-get install -y graylog-server
  else
    log "graylog-server already installed"
  fi

  # Start graylog-server
  if ! start_and_wait graylog-server.service; then
    sudo journalctl -u graylog-server -n 200 --no-pager | sed -n '1,200p' | tee -a "$LOGFILE"
    die "Failed to start graylog-server.service"
  fi

  # Verification (3 levels)
  check_mongodb
  check_datanode
  check_graylog_server

  log "===== All checks passed. Graylog is installed and running. ====="
  log "Access Graylog web UI at: http://<server-ip>:9000 (Username: admin, Password: the one you provided when prompted)"
  echo
  echo "Installer log: $LOGFILE"
}

# run
main "$@"
