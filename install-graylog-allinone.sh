#!/usr/bin/env bash
# install-graylog-allinone-shared-secret.sh
# Ensures datanode and server share the same password_secret and server.conf has root_password_sha2 + data_dir
# For Ubuntu 24.04, all-in-one (MongoDB + Graylog DataNode + Graylog Server)
# Run with sudo

set -euo pipefail
IFS=$'\n\t'

LOG="/var/log/graylog-install-shared-secret.log"
touch "$LOG"
exec > >(tee -a "$LOG") 2>&1

MONGO_CONF="/etc/mongod.conf"
DATANODE_CONF="/etc/graylog/datanode/datanode.conf"
SERVER_CONF="/etc/graylog/server/server.conf"
GRAYLOG_DATA_DIR="/var/lib/graylog-server"
GD_REPO_DEB_URL="https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb"
MONGO_GPG_URL="https://www.mongodb.org/static/pgp/server-8.0.asc"

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

set_mongo_bindipall() {
  echo "Ensuring MongoDB bindIpAll: true"
  [ -f "$MONGO_CONF" ] || { echo "$MONGO_CONF missing"; return 0; }
  cp -av "$MONGO_CONF" "${MONGO_CONF}.bak" || true
  if grep -qE '^\s*bindIpAll\s*[:=]\s*true' "$MONGO_CONF"; then
    echo "bindIpAll already true"
    return
  fi
  if grep -qE '^\s*bindIp\s*[:=]' "$MONGO_CONF"; then
    sed -i -E 's/^(\s*)bindIp\s*[:=].*/\1bindIpAll: true/' "$MONGO_CONF"
    echo "Replaced bindIp with bindIpAll: true"
    return
  fi
  # If net: exists, try to add under first net
  if grep -qE '^\s*net\s*:' "$MONGO_CONF"; then
    awk '
      BEGIN { added=0 }
      { print }
      /^\s*net\s*:/ && added==0 {
        # next line printed, then add bindIpAll
        getline; print $0
        print "  bindIpAll: true"
        added=1
        next
      }
    ' "$MONGO_CONF" > "${MONGO_CONF}.tmp" && mv "${MONGO_CONF}.tmp" "$MONGO_CONF"
    echo "Inserted bindIpAll under net:"
    return
  fi
  # otherwise append net block
  cat >> "$MONGO_CONF" <<EOF

# Added by Graylog installer
net:
  bindIpAll: true
EOF
  echo "Appended net: bindIpAll: true"
}

extract_conf_value() {
  # args: file key
  # returns trimmed value after '=' if present
  local file="$1" key="$2"
  awk -F'=' -v k="$key" '$0 ~ "^"k"[[:space:]]*=" { gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit }' "$file" 2>/dev/null || true
}

ensure_shared_password_secret() {
  # Read existing secrets
  local dn_secret server_secret
  if [ -f "$DATANODE_CONF" ]; then
    dn_secret=$(extract_conf_value "$DATANODE_CONF" "password_secret" || true)
  fi
  if [ -f "$SERVER_CONF" ]; then
    server_secret=$(extract_conf_value "$SERVER_CONF" "password_secret" || true)
  fi

  if [ -n "$dn_secret" ] && [ -n "$server_secret" ]; then
    if [ "$dn_secret" != "$server_secret" ]; then
      echo "WARNING: datanode and server secrets differ. Overwriting server with datanode secret."
      sed -i "s|^password_secret[[:space:]]*=.*|password_secret = $dn_secret|" "$SERVER_CONF" || echo "password_secret = $dn_secret" >> "$SERVER_CONF"
    else
      echo "password_secret already identical and present"
    fi
    return
  fi

  if [ -n "$dn_secret" ] && [ -z "$server_secret" ]; then
    echo "Copying datanode password_secret into server.conf"
    mkdir -p "$(dirname "$SERVER_CONF")"
    sed -i "s|^password_secret[[:space:]]*=.*|password_secret = $dn_secret|" "$SERVER_CONF" 2>/dev/null || echo "password_secret = $dn_secret" >> "$SERVER_CONF"
    return
  fi

  if [ -z "$dn_secret" ] && [ -n "$server_secret" ]; then
    echo "Copying server password_secret into datanode.conf"
    mkdir -p "$(dirname "$DATANODE_CONF")"
    sed -i "s|^password_secret[[:space:]]*=.*|password_secret = $server_secret|" "$DATANODE_CONF" 2>/dev/null || echo "password_secret = $server_secret" >> "$DATANODE_CONF"
    return
  fi

  # neither exists -> generate and write to both
  echo "No existing password_secret found; generating one and writing to datanode.conf and server.conf"
  local newsec
  newsec=$(openssl rand -hex 32)
  mkdir -p "$(dirname "$DATANODE_CONF")" "$(dirname "$SERVER_CONF")"
  # Ensure datanode.conf exists
  [ -f "$DATANODE_CONF" ] || echo "# created by installer" > "$DATANODE_CONF"
  [ -f "$SERVER_CONF" ] || echo "# created by installer" > "$SERVER_CONF"
  sed -i "s|^password_secret[[:space:]]*=.*|password_secret = $newsec|" "$DATANODE_CONF" 2>/dev/null || echo "password_secret = $newsec" >> "$DATANODE_CONF"
  sed -i "s|^password_secret[[:space:]]*=.*|password_secret = $newsec|" "$SERVER_CONF" 2>/dev/null || echo "password_secret = $newsec" >> "$SERVER_CONF"
  echo "Generated secret: ${newsec:0:8}... (trimmed)"
}

ensure_root_sha2() {
  local cur
  cur=$(extract_conf_value "$SERVER_CONF" "root_password_sha2" || true)
  if [ -n "$cur" ]; then
    echo "root_password_sha2 already present in server.conf (preserved)."
    return
  fi
  # prompt for admin password (twice)
  local pass1 pass2 sha
  echo "No root_password_sha2 found in server.conf."
  while true; do
    read -s -p "Enter Graylog admin password: " pass1; echo
    read -s -p "Confirm Graylog admin password: " pass2; echo
    if [ "$pass1" != "$pass2" ]; then
      echo "Passwords do not match. Try again."
    elif [ -z "$pass1" ]; then
      echo "Password cannot be empty."
    else
      break
    fi
  done
  sha=$(echo -n "$pass1" | sha256sum | cut -d' ' -f1)
  sed -i "s|^root_password_sha2[[:space:]]*=.*|root_password_sha2 = $sha|" "$SERVER_CONF" 2>/dev/null || echo "root_password_sha2 = $sha" >> "$SERVER_CONF"
  echo "root_password_sha2 written to server.conf."
}

ensure_data_dir_and_httpbind() {
  # ensure data_dir is set
  if ! grep -qE '^\s*data_dir\s*=' "$SERVER_CONF" 2>/dev/null; then
    echo "Adding data_dir = $GRAYLOG_DATA_DIR to server.conf"
    echo "data_dir = $GRAYLOG_DATA_DIR" >> "$SERVER_CONF"
  else
    # if present but empty, set it
    awk -F'=' '/^data_dir[[:space:]]*=/ { gsub(/^[ \t]+|[ \t]+$/,"",$2); if($2=="") print "empty"; else exit }' "$SERVER_CONF" 2>/dev/null || true
    # replace empty if needed
    sed -i "s|^data_dir[[:space:]]*=.*|data_dir = $GRAYLOG_DATA_DIR|" "$SERVER_CONF"
  fi
  mkdir -p "$GRAYLOG_DATA_DIR"
  chown -R graylog:graylog "$GRAYLOG_DATA_DIR" 2>/dev/null || true

  # ensure http_bind_address
  if ! grep -qE '^\s*http_bind_address\s*=' "$SERVER_CONF" 2>/dev/null; then
    echo "http_bind_address = 0.0.0.0:9000" >> "$SERVER_CONF"
  else
    sed -i "s|^http_bind_address[[:space:]]*=.*|http_bind_address = 0.0.0.0:9000|" "$SERVER_CONF"
  fi
}

ensure_graylog_java_opts() {
  local opts='GRAYLOG_SERVER_JAVA_OPTS="-Xms2g -Xmx2g -server -XX:+UseG1GC -XX:-OmitStackTraceInFastThrow"'
  if [ -f /etc/default/graylog-server ]; then
    if grep -q '^GRAYLOG_SERVER_JAVA_OPTS' /etc/default/graylog-server; then
      sed -i "s|^GRAYLOG_SERVER_JAVA_OPTS=.*|$opts|" /etc/default/graylog-server
    else
      echo "$opts" >> /etc/default/graylog-server
    fi
  else
    echo "$opts" > /etc/default/graylog-server
  fi
}

start_and_wait() {
  local svc="$1"
  systemctl enable "$svc" --now || true
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
  echo "=== Basic checks ==="
  echo "systemd states:"
  systemctl status mongod --no-pager || true
  systemctl status graylog-datanode --no-pager || true
  systemctl status graylog-server --no-pager || true

  echo
  echo "Listening ports (27017, 9200, 9000):"
  ss -tulpen | egrep ':(27017|9200|9000)' || true

  echo
  echo "OpenSearch (Data Node) health (if available):"
  curl -sS --max-time 3 http://127.0.0.1:9200/_cluster/health || echo "No response from 9200"

  echo
  echo "Graylog API status (local):"
  curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:9000/api/system/cluster || echo "No response from 9000"
}

main() {
  require_root
  echo "Starting installer (shared-secret aware)"
  # Install essential packages
  apt_install_if_missing gnupg curl wget apt-transport-https openssl ca-certificates jq

  # Install Java 17
  apt_install_if_missing openjdk-17-jre-headless

  # Install MongoDB if missing
  if ! dpkg -s mongodb-org >/dev/null 2>&1; then
    echo "Installing MongoDB 8.0 repo and package..."
    curl -fsSL "$MONGO_GPG_URL" | gpg --dearmor -o /usr/share/keyrings/mongodb-server-8.0.gpg
    echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" > /etc/apt/sources.list.d/mongodb-org-8.0.list
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y mongodb-org
    apt-mark hold mongodb-org || true
  else
    echo "mongodb-org already installed"
  fi

  set_mongo_bindipall
  systemctl daemon-reload
  start_and_wait mongod || { journalctl -u mongod -n 200 --no-pager; echo "mongod failed to start"; exit 1; }

  # Install Graylog repo
  if ! dpkg -l | grep -q graylog; then
    wget -q "$GD_REPO_DEB_URL" -O /tmp/graylog-repo.deb
    dpkg -i /tmp/graylog-repo.deb || true
    apt-get update -y
  fi

  # Install datanode
  apt_install_if_missing graylog-datanode
  sysctl -w vm.max_map_count=262144 || true
  echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-graylog-datanode.conf || true
  sysctl --system >/dev/null || true
  mkdir -p "$(dirname "$DATANODE_CONF")"
  # ensure datanode has a datanode.conf (if absent create minimal)
  if [ ! -f "$DATANODE_CONF" ]; then
    cat > "$DATANODE_CONF" <<EOF
# minimal datanode config created by installer
password_secret =
opensearch_heap = 1g
mongodb_uri = mongodb://localhost:27017/graylog
EOF
  fi

  # Ensure shared password_secret (this will write to files if needed)
  ensure_shared_password_secret

  start_and_wait graylog-datanode || { journalctl -u graylog-datanode -n 200 --no-pager; echo "graylog-datanode failed to start"; exit 1; }

  # Install graylog-server
  apt_install_if_missing graylog-server

  # Ensure server.conf exists
  mkdir -p "$(dirname "$SERVER_CONF")"
  [ -f "$SERVER_CONF" ] || echo "# server.conf created by installer" > "$SERVER_CONF"

  # Ensure server.conf contains same password_secret and root_password_sha2
  ensure_shared_password_secret
  ensure_root_sha2
  ensure_data_dir_and_httpbind
  ensure_graylog_java_opts

  systemctl daemon-reload
  start_and_wait graylog-server || { journalctl -u graylog-server -n 200 --no-pager; echo "graylog-server failed to start"; exit 1; }

  echo "Installation attempts finished. Running basic checks..."
  basic_checks

  echo
  echo "If everything is healthy you'll be at the preflight page at http://<server-ip>:9000"
  echo "Login: admin / <the password you entered above>"
}

main "$@"
