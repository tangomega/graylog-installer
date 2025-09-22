#!/usr/bin/env bash
# Hardened Graylog + MongoDB installer with verification checks
# Implements Graylog security best practices:
#  - Restrict service bindings to localhost
#  - Enforce MongoDB authentication
#  - Generate secure secrets
#  - Optionally configure TLS reverse proxy with Nginx
#  - Configure strict firewall
#  - Verify each step
#
# Usage:
#   sudo ./installer.sh            # install & harden
#   sudo ./installer.sh --uninstall # remove everything

set -euo pipefail
IFS=$'\n\t'

# ---- Configurable defaults ----
GRAYLOG_HTTP_PORT=9000
GRAYLOG_BIND_ADDR="127.0.0.1"
MONGODB_BIND_ADDR="127.0.0.1"
WIREGUARD_PORT=51820
SYSLOG_TCP_PORT=514
SYSLOG_UDP_PORT=514

# ---- Logging helpers ----
info() { printf "\e[1;36m[INFO]\e[0m %s\n" "$*"; }
ok()   { printf "\e[1;32m[ OK ]\e[0m %s\n" "$*"; }
warn() { printf "\e[1;33m[WARN]\e[0m %s\n" "$*"; }
err()  { printf "\e[1;31m[ERR ]\e[0m %s\n" "$*" >&2; }

# ---- Basic checks ----
require_root() {
  if [ "$EUID" -ne 0 ]; then
    err "This script must be run as root. Use sudo."
    exit 1
  fi
}
confirm_prompt() { read -r -p "$1 [y/N]: " ans; [[ "$ans" =~ ^([yY][eE][sS]|[yY])$ ]]; }
check_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---- Verification helpers ----
verify_service_active() {
  systemctl is-active --quiet "$1" && ok "Service $1 active" || { err "Service $1 not active"; return 1; }
}
verify_port_listening() {
  ss -ltn | awk '{print $4}' | grep -q ":$1\$" && ok "Port $1 listening" || warn "Port $1 not listening"
}
verify_file_perms() {
  [ -f "$1" ] || { warn "$1 missing"; return 1; }
  local u g m; u=$(stat -c %U "$1"); g=$(stat -c %G "$1"); m=$(stat -c %a "$1")
  [ "$u" = "$2" ] && [ "$g" = "$3" ] && [ "$m" = "$4" ] && ok "$1 perms OK" || warn "$1 perms wrong"
}

# ---- Preflight ----
preflight_checks() {
  require_root
  info "Checking dependencies..."
  for cmd in curl wget apt-get systemctl ss openssl jq ufw; do check_cmd "$cmd" || apt-get install -y "$cmd"; done
  info "Checking disk space..."
  [ "$(df --output=avail /var | tail -1)" -lt $((5*1024*1024)) ] && warn "Less than 5GB free in /var"
}

# ---- Install prereqs ----
install_prereqs() {
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y gnupg curl lsb-release apt-transport-https ca-certificates jq openjdk-17-jre-headless ufw
}

# ---- MongoDB ----
add_mongodb_repo() {
  curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | gpg --dearmor >/usr/share/keyrings/mongodb-server-8.0.gpg
  echo "deb [signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/8.0 multiverse" > /etc/apt/sources.list.d/mongodb-org-8.0.list
  apt-get update -y
}
install_mongodb() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y mongodb-org
  systemctl enable --now mongod
  verify_service_active mongod
}
configure_mongodb_secure() {
  sed -i "s/^ *bindIp.*/  bindIp: ${MONGODB_BIND_ADDR}/" /etc/mongod.conf || true
  grep -q "^security:" /etc/mongod.conf || echo -e "\nsecurity:\n  authorization: enabled" >> /etc/mongod.conf
  systemctl restart mongod
  verify_service_active mongod
  read -rp "MongoDB admin user [graylog]: " mongo_user; mongo_user=${mongo_user:-graylog}
  read -rsp "MongoDB admin password: " mongo_pass; echo
  mongo admin --eval "db.createUser({user:'$mongo_user',pwd:'$mongo_pass',roles:[{role:'userAdminAnyDatabase',db:'admin'},{role:'readWriteAnyDatabase',db:'admin'}]})" || true
  mkdir -p /etc/graylog/credentials
  echo "$mongo_user" > /etc/graylog/credentials/mongo_user
  echo "$mongo_pass" > /etc/graylog/credentials/mongo_pass
  chmod 600 /etc/graylog/credentials/*
}

# ---- Graylog ----
add_graylog_repo_and_install() {
  wget -q -O /tmp/graylog-repo.deb https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb
  dpkg -i /tmp/graylog-repo.deb || true
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y graylog-datanode graylog-server
}
configure_graylog_secure() {
  password_secret_file="/etc/graylog/password_secret"
  [ -f "$password_secret_file" ] || openssl rand -hex 64 > "$password_secret_file"
  chmod 400 "$password_secret_file"
  password_secret=$(cat "$password_secret_file")
  sed -i "s|^password_secret.*|password_secret = ${password_secret}|" /etc/graylog/server/server.conf || echo "password_secret = ${password_secret}" >> /etc/graylog/server/server.conf
  mongo_user=$(cat /etc/graylog/credentials/mongo_user)
  mongo_pass=$(cat /etc/graylog/credentials/mongo_pass)
  mongodb_uri="mongodb://${mongo_user}:${mongo_pass}@127.0.0.1:27017/graylog?authSource=admin"
  grep -q "^mongodb_uri" /etc/graylog/server/server.conf && sed -i "s|^mongodb_uri.*|mongodb_uri = ${mongodb_uri}|" /etc/graylog/server/server.conf || echo "mongodb_uri = ${mongodb_uri}" >> /etc/graylog/server/server.conf
  sed -i "s|^http_bind_address.*|http_bind_address = ${GRAYLOG_BIND_ADDR}:${GRAYLOG_HTTP_PORT}|" /etc/graylog/server/server.conf || echo "http_bind_address = ${GRAYLOG_BIND_ADDR}:${GRAYLOG_HTTP_PORT}" >> /etc/graylog/server/server.conf
}

# ---- Optional TLS ----
configure_nginx_tls() {
  confirm_prompt "Configure Nginx TLS reverse proxy?" || return 0
  apt-get install -y nginx
  read -rp "FQDN for TLS cert: " server_name
  read -rp "Path to cert [/etc/ssl/certs/graylog.crt]: " tls_cert; tls_cert=${tls_cert:-/etc/ssl/certs/graylog.crt}
  read -rp "Path to key [/etc/ssl/private/graylog.key]: " tls_key; tls_key=${tls_key:-/etc/ssl/private/graylog.key}
  cat > /etc/nginx/sites-available/graylog <<EOF
server {
    listen 443 ssl;
    server_name ${server_name};
    ssl_certificate ${tls_cert};
    ssl_certificate_key ${tls_key};
    location / {
        proxy_pass http://${GRAYLOG_BIND_ADDR}:${GRAYLOG_HTTP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Graylog-Server-URL https://${server_name};
    }
}
server { listen 80; server_name ${server_name}; return 301 https://\$host\$request_uri; }
EOF
  ln -sf /etc/nginx/sites-available/graylog /etc/nginx/sites-enabled/
  nginx -t && systemctl restart nginx
  verify_service_active nginx
}

# ---- Firewall ----
configure_firewall() {
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp comment 'SSH'
  ufw allow "${SYSLOG_TCP_PORT}"/tcp comment 'Syslog TCP'
  ufw allow "${SYSLOG_UDP_PORT}"/udp comment 'Syslog UDP'
  systemctl is-active --quiet nginx && ufw allow 443/tcp comment 'HTTPS' && ufw allow 80/tcp comment 'HTTP'
  ufw --force enable
  ufw status verbose
}

# ---- Services ----
start_and_verify_services() {
  systemctl enable --now graylog-datanode graylog-server
  sleep 5
  verify_service_active graylog-server
  curl -sI http://${GRAYLOG_BIND_ADDR}:${GRAYLOG_HTTP_PORT} | head -n1
}

# ---- Uninstall ----
uninstall_everything() {
  systemctl stop graylog-server graylog-datanode mongod nginx || true
  apt-get purge -y graylog-server graylog-datanode mongodb-org nginx || true
  apt-get autoremove -y || true
  rm -rf /etc/graylog /var/lib/mongodb /var/log/graylog* /var/log/mongodb
}

# ---- Main ----
main() {
  case "${1:-}" in
    --uninstall) uninstall_everything; exit 0;;
  esac
  preflight_checks
  install_prereqs
  add_mongodb_repo
  install_mongodb
  configure_mongodb_secure
  add_graylog_repo_and_install
  configure_graylog_secure
  configure_nginx_tls
  configure_firewall
  start_and_verify_services
}
main "$@"
