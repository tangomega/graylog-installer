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
         MongoDB + Graylog Installer (with hacker progress bar 🏃)
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

# --- Stick Figure Progress Bar ---
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

# --- APT Install Wrapper ---
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
  section "Preparing minimal system prerequisites"
  type_echo "[HACKER] Ensuring prerequisites are present..."
  apt_with_animation "Installing prerequisites" ca-certificates apt-transport-https gnupg curl wget lsb-release software-properties-common openssl jq
}

add_mongodb_repo() {
  section "Adding MongoDB repository"
  type_echo "[HACKER] Adding official MongoDB APT repo..."
  local codename
  codename=$(lsb_release -sc)
  curl -fsSL https://pgp.mongodb.com/server-8.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor
  echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu ${codename}/mongodb-org/8.0 multiverse" \
    | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list >/dev/null
  sudo apt-get update -y >/dev/null
}

install_mongodb() {
  section "MongoDB Installation"
  type_echo "[HACKER] Deploying MongoDB v8.0 to localhost..."
  log "Stopping mongod if running"
  sudo systemctl stop mongod.service >/dev/null 2>&1 || true

  if dpkg-query -W -f='${Status}' mongodb-org 2>/dev/null | grep -q "installed"; then
    log "Purging existing mongodb-org installation"
    sudo apt-get purge -y mongodb-org* >/dev/null 2>&1 || true
    sudo rm -rf /var/log/mongodb /var/lib/mongodb
  else
    log "No existing mongodb-org package detected; skipping purge"
  fi

  apt_with_animation "Installing MongoDB (8.0)" mongodb-org

  log "Holding mongodb-org packages"
  sudo apt-mark hold mongodb-org* >/dev/null || true

  if grep -qE '^\s*bindIp' /etc/mongod.conf >/dev/null 2>&1; then
    sudo sed -i -r 's@(^\s*bindIp\s*:\s*).*@\10.0.0.0@' /etc/mongod.conf
  else
    echo -e "\nnet:\n  bindIp: 0.0.0.0" | sudo tee -a /etc/mongod.conf >/dev/null
  fi

  sudo systemctl daemon-reload
  sudo systemctl enable --now mongod.service
}

add_and_install_graylog() {
  section "Graylog DataNode & Server Installation"
  type_echo "[HACKER] Installing Graylog components..."
  apt_with_animation "Installing Java 17 + tools" openjdk-17-jre-headless jq

  log "Adding Graylog repository"
  wget -q https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb -O /tmp/graylog-repo.deb
  sudo dpkg -i /tmp/graylog-repo.deb >/dev/null 2>&1 || true
  sudo apt-get update -y >/dev/null

  apt_with_animation "Installing Graylog datanode + server" graylog-datanode graylog-server

  echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-graylog-datanode.conf >/dev/null
  sudo sysctl --system >/dev/null

  sudo sed -i "/^mongodb_uri/c\mongodb_uri = mongodb://127.0.0.1:27017/graylog" /etc/graylog/datanode/datanode.conf || true
  if ! grep -q '^opensearch_heap' /etc/graylog/datanode/datanode.conf 2>/dev/null; then
    echo "opensearch_heap = 2g" | sudo tee -a /etc/graylog/datanode/datanode.conf >/dev/null
  fi

  sudo systemctl enable --now graylog-datanode.service
  sudo systemctl enable --now graylog-server.service
}

main() {
  clear
  ascii_banner
  sleep 1

  ensure_prereqs
  add_mongodb_repo
  install_mongodb
  add_and_install_graylog

  section "System Ready"
  type_echo "[HACKER] Graylog is alive (if services are up)."
  echo -e "${CYAN}Web UI:${RESET} http://<server-ip>:9000"
  echo -e "${CYAN}Tail logs:${RESET} sudo tail -f /var/log/graylog-server/server.log"
}

main "$@"
