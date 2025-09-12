#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Colors & Effects
GREEN="\033[0;32m"
CYAN="\033[0;36m"
MAGENTA="\033[0;35m"
RESET="\033[0m"
BOLD="\033[1m"

DEBIAN_FRONTEND=noninteractive
export DEBIAN_FRONTEND

ascii_banner() {
cat << "EOF"
___________                      ___________           .__        _________               __                         
\__    ___/______ __ __   ____   \__    ___/___   ____ |  |__    /   _____/__.__. _______/  |_  ____   _____   ______
  |    |  \_  __ \  |  \_/ __ \    |    |_/ __ \_/ ___\|  |  \   \_____  <   |  |/  ___/\   __\/ __ \ /     \ /  ___/
  |    |   |  | \/  |  /\  ___/    |    |\  ___/\  \___|   Y  \  /        \___  |\___ \  |  | \  ___/|  Y Y  \\___ \ 
  |____|   |__|  |____/  \___  >   |____| \___  >\___  >___|  / /_______  / ____/____  > |__|  \___  >__|_|  /____  >
                             \/               \/     \/     \/          \/\/         \/            \/      \/     \/                    
         MongoDB + Graylog Installer (0.1)
EOF
}

type_echo() {
  local text="$1"
  local delay="${2:-0.01}"
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

spinner_with_runner() {
  local pid=$1
  local msg=$2
  local delay=0.1
  local frames=("🏃" "🏃‍♂️" "🏃‍♀️")
  local width=30
  local progress=0

  echo -ne "$msg\n"

  while kill -0 $pid 2>/dev/null; do
    local filled=$((progress % (width+1)))
    local empty=$((width - filled))
    local bar=$(printf "%0.s#" $(seq 1 $filled))
    local space=$(printf "%0.s " $(seq 1 $empty))
    local frame=${frames[$((progress % ${#frames[@]}))]}
    printf "\r[%s%s] %s %s" "$bar" "$space" "$frame" "$msg"
    sleep $delay
    progress=$((progress+1))
  done

  printf "\r[%s] ✅ %s\n" "$(printf "%0.s#" $(seq 1 $width))" "$msg"
}

apt_with_animation() {
  local msg=$1; shift
  sudo apt-get update -y >/dev/null 2>&1 &
  spinner_with_runner $! "Updating apt sources..."
  wait $! || true

  sudo apt-get install -y "$@" >/dev/null 2>&1 &
  spinner_with_runner $! "$msg"
  wait $! || true
}

ensure_prereqs() {
  section "Preparing System Prerequisites"
  type_echo "[HACKER] Ensuring essential tools are present..."
  apt_with_animation "Installing prerequisites" gnupg curl wget apt-transport-https openssl ca-certificates jq openjdk-17-jre-headless lsb-release
}

add_mongodb_repo() {
  section "Adding MongoDB Repository"
  type_echo "[HACKER] Configuring MongoDB APT repository..."
  curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor
  echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list >/dev/null
  sudo apt-get update -y >/dev/null
}

install_mongodb() {
  section "MongoDB Installation"
  type_echo "[HACKER] Deploying MongoDB..."
  log "Stopping mongod if running"
  sudo systemctl stop mongod.service >/dev/null 2>&1 || true

  log "Purging old MongoDB installation"
  sudo apt-get purge -y mongodb-org* >/dev/null 2>&1 || true
  sudo rm -rf /var/log/mongodb /var/lib/mongodb

  apt_with_animation "Installing MongoDB 8.0" mongodb-org
  sudo apt-mark hold mongodb-org >/dev/null

  log "Configuring mongod bind IP"
  sudo sed -i '/bindIp/c\  bindIpAll: true' /etc/mongod.conf

  sudo systemctl daemon-reload
  sleep 2
  sudo systemctl enable mongod.service
  sleep 2
  sudo systemctl start mongod.service
  sleep 2
}

install_graylog() {
  section "Graylog DataNode & Server Installation"
  type_echo "[HACKER] Installing Graylog components..."
  apt_with_animation "Installing Graylog tools" graylog-datanode graylog-server

  log "Setting DataNode configurations"
  echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-graylog-datanode.conf >/dev/null
  sudo sysctl --system >/dev/null

  sudo sed -i "/password_secret/c\\password_secret = $(openssl rand -hex 32)" /etc/graylog/datanode/datanode.conf
  sudo sed -i "/mongodb_uri/c\\mongodb_uri = mongodb://127.0.0.1:27017/graylog" /etc/graylog/datanode/datanode.conf
  echo "opensearch_heap = 4g" | sudo tee -a /etc/graylog/datanode/datanode.conf >/dev/null

  sudo systemctl daemon-reload
  sleep 2
  sudo systemctl enable graylog-datanode.service
  sleep 2
  sudo systemctl start graylog-datanode
  sleep 2

  log "Configuring Graylog Server"
  sudo sed -i "/password_secret/c$(sed -n '/password_secret/{p;q}' /etc/graylog/datanode/datanode.conf)" /etc/graylog/server/server.conf
  sudo sed -i '0,/http_bind_address/{s|.*http_bind_address.*|http_bind_address = 0.0.0.0:9000|}' /etc/graylog/server/server.conf

  read -sp "Enter Password for Graylog Admin: " pw && echo
  hash=$(echo -n "$pw" | sha256sum | cut -d' ' -f1)
  sudo sed -i "/^root_password_sha2 =/c\root_password_sha2 = $hash" /etc/graylog/server/server.conf

  sudo sed -i '/^GRAYLOG_SERVER_JAVA_OPTS="-Xms1g/c\GRAYLOG_SERVER_JAVA_OPTS="-Xms2g -Xmx2g -server -XX:+UseG1GC -XX:-OmitStackTraceInFastThrow"' /etc/default/graylog-server
  sudo systemctl daemon-reload
  sleep 2
  sudo systemctl enable graylog-server.service
  sleep 2
  sudo systemctl start graylog-server.service
  sleep 5

  log "Graylog Server is live! Tail logs to monitor activity:"
  echo -e "${CYAN}sudo tail -f /var/log/graylog-server/server.log${RESET}"
}

main() {
  clear
  ascii_banner
  sleep 1

  ensure_prereqs
  add_mongodb_repo
  install_mongodb
  install_graylog

  section "System Ready"
  type_echo "[HACKER] MongoDB & Graylog deployed successfully!"
}

main "$@"
