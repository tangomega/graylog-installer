#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Colors & Effects
GREEN="\033[0;32m"
CYAN="\033[0;36m"
MAGENTA="\033[0;35m"
RESET="\033[0m"
BOLD="\033[1m"

ascii_banner() {
cat << "EOF"
___________                      ___________           .__        _________               __                         
\__    ___/______ __ __   ____   \__    ___/___   ____ |  |__    /   _____/__.__. _______/  |_  ____   _____   ______
  |    |  \_  __ \  |  \_/ __ \    |    |_/ __ \_/ ___\|  |  \   \_____  <   |  |/  ___/\   __\/ __ \ /     \ /  ___/
  |    |   |  | \/  |  /\  ___/    |    |\  ___/\  \___|   Y  \  /        \___  |\___ \  |  | \  ___/|  Y Y  \\___ \ 
  |____|   |__|  |____/  \___  >   |____| \___  >\___  >___|  / /_______  / ____/____  > |__|  \___  >__|_|  /____  >
                             \/               \/     \/     \/          \/\/         \/            \/      \/     \/                    
         MongoDB + Graylog Installer
EOF
}

type_echo() {
  local text="$1"
  local delay="${2:-0.02}"
  for ((i=0; i<${#text}; i++)); do
    printf "%s" "${text:$i:1}"
    sleep "$delay"
  done
  printf "\n"
}

section() {
  echo -e "\n${CYAN}============================================================${RESET}"
  echo -e "${MAGENTA}${BOLD}>> $1${RESET}"
  echo -e "${CYAN}============================================================${RESET}\n"
}

log() {
  echo -e "${GREEN}[+]${RESET} $1"
}

main() {
  clear
  ascii_banner
  sleep 1

  section "MongoDB Installation"
  type_echo "[HACKER] Deploying MongoDB v8.0 to localhost..."
  log "Stopping service"
  sudo systemctl stop mongod || true

  log "Purging old versions"
  sudo apt-get purge -y mongodb-org* >/dev/null 2>&1 || true
  sudo rm -rf /var/log/mongodb /var/lib/mongodb

  log "Installing prerequisites"
  sudo apt-get install -y gnupg curl >/dev/null 2>&1

  log "Adding MongoDB repository"
  curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc \
    | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor
  echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] \
https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" \
    | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list >/dev/null
  sudo apt-get update -y >/dev/null

  log "Installing MongoDB"
  sudo apt-get install -y mongodb-org >/dev/null
  sudo apt-mark hold mongodb-org

  log "Configuring bind address"
  sudo sed -i '/bindIp/c\  bindIpAll: true' /etc/mongod.conf
  sudo systemctl enable --now mongod

  section "Graylog DataNode Installation"
  type_echo "[HACKER] Initializing Graylog DataNode..."
  log "Removing old DataNode"
  sudo systemctl stop graylog-datanode || true
  sudo apt purge --autoremove -y graylog-datanode >/dev/null 2>&1 || true
  sudo rm -rf /etc/graylog/datanode /var/lib/graylog-datanode /var/log/graylog-datanode
  sudo apt update -y >/dev/null

  log "Installing prerequisites"
  sudo apt install -y gnupg curl wget apt-transport-https openssl ca-certificates jq openjdk-17-jre-headless >/dev/null

  log "Adding Graylog repo"
  wget -q https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb
  sudo dpkg -i graylog-6.3-repository_latest.deb >/dev/null
  sudo apt-get update -y >/dev/null
  sudo apt-get install -y graylog-datanode >/dev/null

  log "Tuning kernel"
  echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-graylog-datanode.conf >/dev/null
  sudo sysctl --system >/dev/null

  log "Configuring datanode.conf"
  sudo sed -i "/password_secret/c\\password_secret = $(openssl rand -hex 32)" /etc/graylog/datanode/datanode.conf
  sudo sed -i "/mongodb_uri/c\\mongodb_uri = mongodb://127.0.0.1:27017/graylog" /etc/graylog/datanode/datanode.conf
  echo "opensearch_heap = 4g" | sudo tee -a /etc/graylog/datanode/datanode.conf >/dev/null

  sudo systemctl enable --now graylog-datanode

  section "Graylog Server Installation"
  type_echo "[HACKER] Bringing Graylog Server online..."
  log "Installing Graylog Server"
  sudo apt-get install -y graylog-server >/dev/null

  log "Syncing password_secret"
  sudo sed -i "/password_secret/c$(sed -n '/password_secret/{p;q}' /etc/graylog/datanode/datanode.conf)" /etc/graylog/server/server.conf

  log "Setting bind address"
  sudo sed -i '0,/http_bind_address/{s|.*http_bind_address.*|http_bind_address = 0.0.0.0:9000|}' /etc/graylog/server/server.conf

  log "Setting admin password"
  read -sp "Enter Graylog admin password: " pw && echo
  hash=$(echo -n "$pw" | sha256sum | cut -d' ' -f1)
  sudo sed -i "/^root_password_sha2 =/c\root_password_sha2 = $hash" /etc/graylog/server/server.conf

  log "Tuning JVM options"
  sudo sed -i '/^GRAYLOG_SERVER_JAVA_OPTS="/c\GRAYLOG_SERVER_JAVA_OPTS="-Xms2g -Xmx2g -server -XX:+UseG1GC -XX:-OmitStackTraceInFastThrow"' /etc/default/graylog-server

  log "Starting service"
  sudo systemctl enable --now graylog-server.service

  section "System Ready"
  type_echo "[HACKER] Graylog is alive. Access it at: http://localhost:9000"
  echo -e "${CYAN}Use: ${RESET}sudo tail -f /var/log/graylog-server/server.log"
}

main "$@"
