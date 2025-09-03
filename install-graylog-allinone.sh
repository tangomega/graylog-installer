#!/usr/bin/env bash
# install-graylog-allinone.sh
# Installs MongoDB 7.0, Graylog Data Node, and Graylog Server on a fresh Ubuntu machine (20.04/22.04).
# Noninteractive. Configure with environment variables listed below or accept sensible defaults.

set -euo pipefail
IFS=$'\n\t'

### --- User-configurable environment variables (export before running or edit here) ---
: "${ADMIN_PASSWORD:="tts3369"}"          # If empty, script will generate and print a random admin password.
: "${MONGO_BIND_IP:="127.0.0.1"}"  # Use 0.0.0.0 or specific IP if you want remote access
: "${GRAYLOG_HTTP_BIND:="0.0.0.0:9000"}"   # Graylog web/API listen address
: "${JOURNAL_MAX_AGE:="72h"}"      # message_journal_max_age
: "${JOURNAL_MAX_SIZE:="90gb"}"    # message_journal_max_size (adjust to expected 72h volume)
: "${NONINTERACTIVE:="1"}"         # set to 0 if you want manual editing - not recommended
# END config

# Helper: require root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root (sudo)."
  exit 1
fi

echo "Starting Graylog all-in-one automated install..."
echo "Based on Graylog docs: https://go2docs.graylog.org/current/downloading_and_installing_graylog/ubuntu_installation.htm"

apt_update() {
  apt-get update -y
}

install_packages() {
  echo "--- Installing prerequisite packages ---"
  apt-get install -y gnupg curl wget apt-transport-https ca-certificates lsb-release software-properties-common
}

set_timezone() {
  echo "--- Setting server timezone to UTC ---"
  timedatectl set-timezone UTC
}

detect_ubuntu_codename() {
  . /etc/os-release
  CODENAME=$(lsb_release -cs || echo "$UBUNTU_CODENAME" || echo "jammy")
  echo "Detected Ubuntu codename: $CODENAME"
}

install_mongodb() {
  echo "--- Installing MongoDB 7.0 ---"
  apt-get install -y gnupg curl || true
  curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | gpg --dearmor -o /usr/share/keyrings/mongodb-server-7.0.gpg
  # Use detected codename (jammy/focal)
  echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list
  apt-get update -y
  apt-get install -y mongodb-org
  # Prevent automatic upgrades of mongodb-org packages
  apt-mark hold mongodb-org
  # Configure bind (replace or add bindIpAll or bindIp)
  echo "--- Configuring MongoDB bind settings (bindIp/bindIpAll) ---"
  if grep -qE '^\s*bindIpAll' /etc/mongod.conf 2>/dev/null; then
    sed -ri "s|^\s*bindIpAll:.*|bindIpAll: false|" /etc/mongod.conf || true
  fi
  # Set net section to desired bind
  # Use yq would be ideal; we'll use a safe approach: replace net: block if present, otherwise append
  awk -v bind="${MONGO_BIND_IP}" '
    BEGIN{in_net=0; done=0}
    {
      if($0 ~ /^[[:space:]]*net:/){print "net:"; print "  port: 27017"; if(bind == "0.0.0.0" || bind == "127.0.0.1"){ if(bind=="0.0.0.0"){print "  bindIpAll: true"} else {print "  bindIp: " bind}} else {print "  bindIp: " bind}; in_net=1; done=1; next}
      if(in_net){ if($0 ~ /^[[:space:]]*[a-zA-Z]/){in_net=0} else next }
      print
    }
    END{ if(done==0){ print ""; print "net:"; print "  port: 27017"; if(bind == "0.0.0.0"){print "  bindIpAll: true"} else {print "  bindIp: " bind } } }
  ' /etc/mongod.conf > /tmp/mongod.conf.new && mv /tmp/mongod.conf.new /etc/mongod.conf
  systemctl daemon-reload
  systemctl enable --now mongod.service
  echo "MongoDB installed and started."
}

install_graylog_datanode() {
  echo "--- Installing Graylog Data Node ---"
  cd /tmp
  wget -q "https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb" -O graylog-repo.deb
  dpkg -i graylog-repo.deb || true
  apt-get update -y
  apt-get install -y graylog-datanode
  # vm.max_map_count
  echo "vm.max_map_count=262144" | tee /etc/sysctl.d/99-graylog-datanode.conf
  sysctl --system
}

compute_heap_sizes() {
  echo "--- Computing heap sizes based on total system RAM ---"
  # MemTotal in kB
  mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
  mem_mb=$((mem_kb/1024))
  mem_gb=$(( (mem_mb + 1023) / 1024 ))  # round up
  echo "System RAM: ${mem_gb} GB"
  # Data Node: half system memory up to 31G
  half_gb=$(( mem_gb / 2 ))
  if [ "$half_gb" -lt 1 ]; then half_gb=1; fi
  if [ "$half_gb" -gt 31 ]; then half_gb=31; fi
  OPENSEARCH_HEAP="${half_gb}g"
  # Graylog server: half system memory up to 16G
  gray_half=$(( mem_gb / 2 ))
  if [ "$gray_half" -lt 1 ]; then gray_half=1; fi
  if [ "$gray_half" -gt 16 ]; then gray_half=16; fi
  GRAYLOG_HEAP="${gray_half}g"
  echo "Data Node heap -> ${OPENSEARCH_HEAP}, Graylog heap -> ${GRAYLOG_HEAP}"
}

# Insert or replace key = value in a config file (key without regex chars)
set_config_kv() {
  local file="$1" key="$2" value="$3"
  # If key exists (with optional spaces and optional commented), replace; otherwise append
  if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$file" 2>/dev/null; then
    sed -ri "s|^[[:space:]]*(${key})[[:space:]]*=.*$|\\1 = ${value}|" "$file"
  else
    echo "${key} = ${value}" >> "$file"
  fi
}

configure_datanode() {
  echo "--- Configuring Graylog Data Node ---"
  DN_CONF="/etc/graylog/datanode/datanode.conf"
  if [ ! -f "$DN_CONF" ]; then
    echo "WARNING: $DN_CONF not found yet. It should exist after package install. Creating skeleton..."
    mkdir -p "$(dirname "$DN_CONF")"
    touch "$DN_CONF"
  fi
  # generate password_secret
  PASSWORD_SECRET=$(openssl rand -hex 32)
  set_config_kv "$DN_CONF" "password_secret" "\"${PASSWORD_SECRET}\""
  set_config_kv "$DN_CONF" "opensearch_heap" "${OPENSEARCH_HEAP}"
  # Use local mongodb uri unless DATANODE_MONGODB_URI env var set
  : "${DATANODE_MONGODB_URI:="mongodb://localhost:27017/graylog"}"
  set_config_kv "$DN_CONF" "mongodb_uri" "\"${DATANODE_MONGODB_URI}\""
  chown graylog:graylog "$DN_CONF" || true
  systemctl daemon-reload
  systemctl enable --now graylog-datanode.service
  echo "Data Node configured; password_secret generated and stored in $DN_CONF."
}

install_graylog_server() {
  echo "--- Installing Graylog Server ---"
  apt-get update -y
  # install graylog server package (open-source)
  apt-get install -y graylog-server
  echo "Graylog server package installed."
}

configure_graylog_server() {
  echo "--- Configuring Graylog Server ---"
  SERVER_CONF="/etc/graylog/server/server.conf"
  DEFAULT_FILE="/etc/default/graylog-server"
  if [ ! -f "$SERVER_CONF" ]; then
    echo "ERROR: $SERVER_CONF missing. Aborting."
    exit 1
  fi

  # Ensure we have the same password_secret in server.conf as datanode.conf
  if [ -z "${PASSWORD_SECRET:-}" ]; then
    # Try to read from datanode.conf if present
    if [ -f /etc/graylog/datanode/datanode.conf ]; then
      # extract between quotes or without
      PASSWORD_SECRET=$(awk -F'=' '/password_secret/ {gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit}' /etc/graylog/datanode/datanode.conf | sed 's/^"//; s/"$//')
    fi
  fi
  if [ -z "${PASSWORD_SECRET:-}" ]; then
    echo "No password_secret available; generating new one..."
    PASSWORD_SECRET=$(openssl rand -hex 32)
  fi
  set_config_kv "$SERVER_CONF" "password_secret" "\"${PASSWORD_SECRET}\""

  # admin password: if not provided, generate one
  if [ -z "${ADMIN_PASSWORD}" ]; then
    ADMIN_PASSWORD=$(openssl rand -base64 18)
    echo "Generated admin password: ${ADMIN_PASSWORD}"
  fi
  ROOT_PW_SHA2=$(echo -n "${ADMIN_PASSWORD}" | sha256sum | awk '{print $1}')
  set_config_kv "$SERVER_CONF" "root_password_sha2" "${ROOT_PW_SHA2}"

  # HTTP bind
  set_config_kv "$SERVER_CONF" "http_bind_address" "\"${GRAYLOG_HTTP_BIND}\""

  # Journal settings
  set_config_kv "$SERVER_CONF" "message_journal_max_age" "${JOURNAL_MAX_AGE}"
  set_config_kv "$SERVER_CONF" "message_journal_max_size" "${JOURNAL_MAX_SIZE}"

  # GRAYLOG_SERVER_JAVA_OPTS in /etc/default/graylog-server
  if [ -f "$DEFAULT_FILE" ]; then
    # Replace or add the Java opts line
    sed -ri "s|^GRAYLOG_SERVER_JAVA_OPTS=.*$|GRAYLOG_SERVER_JAVA_OPTS=\"-Xms${GRAYLOG_HEAP} -Xmx${GRAYLOG_HEAP} -server -XX:+UseG1GC -XX:-OmitStackTraceInFastThrow\"|" "$DEFAULT_FILE" || true
    if ! grep -q '^GRAYLOG_SERVER_JAVA_OPTS=' "$DEFAULT_FILE"; then
      echo "GRAYLOG_SERVER_JAVA_OPTS=\"-Xms${GRAYLOG_HEAP} -Xmx${GRAYLOG_HEAP} -server -XX:+UseG1GC -XX:-OmitStackTraceInFastThrow\"" >> "$DEFAULT_FILE"
    fi
  else
    echo "GRAYLOG_SERVER_JAVA_OPTS=\"-Xms${GRAYLOG_HEAP} -Xmx${GRAYLOG_HEAP} -server -XX:+UseG1GC -XX:-OmitStackTraceInFastThrow\"" > "$DEFAULT_FILE"
  fi

  systemctl daemon-reload
  systemctl enable --now graylog-server.service
  echo "Graylog server configured and started."
}

print_summary() {
  echo
  echo "================ INSTALL SUMMARY ================"
  echo "MongoDB bind address: ${MONGO_BIND_IP}"
  echo "Graylog web/API: http://${GRAYLOG_HTTP_BIND}"
  echo
  echo "Important values (record these):"
  echo "  password_secret: ${PASSWORD_SECRET}"
  echo "  admin password (plain): ${ADMIN_PASSWORD}"
  echo "  admin password SHA256: ${ROOT_PW_SHA2}"
  echo
  echo "Services started: mongod, graylog-datanode, graylog-server"
  echo "Log locations (use journalctl -u <service> -f):"
  echo "  mongod:   journalctl -u mongod -f"
  echo "  datanode: journalctl -u graylog-datanode -f"
  echo "  server:   journalctl -u graylog-server -f"
  echo
  echo "If you need to change more config options, edit:"
  echo "  /etc/mongod.conf"
  echo "  /etc/graylog/datanode/datanode.conf"
  echo "  /etc/graylog/server/server.conf"
  echo "=================================================="
}

## ---- Run steps ----
apt_update
install_packages
set_timezone
detect_ubuntu_codename
install_mongodb
install_graylog_datanode
compute_heap_sizes
configure_datanode
install_graylog_server
configure_graylog_server
print_summary

exit 0
