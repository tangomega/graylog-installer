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
 _________  ________  ___  ___  _______           _________  _______   ________  ___  ___          ________       ___    ___ ________  _________  _______   _____ ______   ________      
|\___   ___\\   __  \|\  \|\  \|\  ___ \         |\___   ___\\  ___ \ |\   ____\|\  \|\  \        |\   ____\     |\  \  /  /|\   ____\|\___   ___\\  ___ \ |\   _ \  _   \|\   ____\     
\|___ \  \_\ \  \|\  \ \  \\\  \ \   __/|        \|___ \  \_\ \   __/|\ \  \___|\ \  \\\  \       \ \  \___|_    \ \  \/  / | \  \___|\|___ \  \_\ \   __/|\ \  \\\__\ \  \ \  \___|_    
     \ \  \ \ \   _  _\ \  \\\  \ \  \_|/__           \ \  \ \ \  \_|/_\ \  \    \ \   __  \       \ \_____  \    \ \    / / \ \_____  \   \ \  \ \ \  \_|/_\ \  \\|__| \  \ \_____  \   
      \ \  \ \ \  \\  \\ \  \\\  \ \  \_|\ \           \ \  \ \ \  \_|\ \ \  \____\ \  \ \  \       \|____|\  \    \/  /  /   \|____|\  \   \ \  \ \ \  \_|\ \ \  \    \ \  \|____|\  \  
       \ \__\ \ \__\\ _\\ \_______\ \_______\           \ \__\ \ \_______\ \_______\ \__\ \__\        ____\_\  \ __/  / /       ____\_\  \   \ \__\ \ \_______\ \__\    \ \__\____\_\  \ 
        \|__|  \|__|\|__|\|_______|\|_______|            \|__|  \|_______|\|_______|\|__|\|__|       |\_________\\___/ /       |\_________\   \|__|  \|_______|\|__|     \|__|\_________\
                                                                                                     \|_________\|___|/        \|_________|                                  \|_________|
                                                                                                                                                                                                                                                                                                                 
         MongoDB + Graylog Installer (v0.5)
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

# --- APT Purge Wrapper ---
purge_with_animation() {
  local msg=$1; shift
  sudo apt-get purge -y "$@" >/dev/null 2>&1 &
  spinner_with_runner $! "$msg"
  wait $! || true
  sudo apt-get autoremove -y >/dev/null 2>&1 &
  spinner_with_runner $! "Cleaning up unused dependencies..."
  wait $! || true
}

ensure_prereqs() {
  section "Installing Essential Packages"
  type_echo "Ensuring prerequisites are present..."
  apt_with_animation "Installing gnupg, curl, lsb-release" gnupg curl lsb-release net-tools
}

add_mongodb_repo() {
  section "Installing MongoDB"
  type_echo "Adding official MongoDB APT repo..."
  curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor >/dev/null 2>&1 &
  spinner_with_runner $! "Adding MongoDB GPG key..."
  echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list >/dev/null
  log "Repository configured."
  sudo apt-get update -y >/dev/null 2>&1 &
  spinner_with_runner $! "Updating package lists..."
  apt_with_animation "Installing MongoDB" mongodb-org
  sudo apt-mark hold mongodb-org >/dev/null || true
  log "MongoDB version held."
}

configure_mongodb() {
  section "Configuring MongoDB"
  type_echo "Configuring MongoDB for operation..."
  sudo sed -i '/bindIp/c\  bindIp: 127.0.0.1' /etc/mongod.conf
  log "Bind configuration updated to localhost."
  # Enable authentication
  sudo sed -i '/^#security:/a security:\n  authorization: enabled' /etc/mongod.conf
  log "MongoDB authentication enabled."
  sudo systemctl daemon-reload >/dev/null 2>&1
  sleep 2
  log "Daemon reloaded."
  sudo systemctl enable mongod.service >/dev/null 2>&1
  sleep 2
  log "MongoDB service enabled."
  sudo systemctl start mongod.service >/dev/null 2>&1
  sleep 2
  log "MongoDB service started."
}

install_graylog_datanode() {
  section "Starting Graylog DataNode Installer"
  type_echo "Installing Graylog DataNode components..."
  apt_with_animation "Installing additional essentials" gnupg curl wget apt-transport-https openssl ca-certificates jq openjdk-17-jre-headless
  wget https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb -O /tmp/graylog-repo.deb >/dev/null 2>&1 &
  spinner_with_runner $! "Downloading Graylog repository package..."
  sudo dpkg -i /tmp/graylog-repo.deb >/dev/null 2>&1 || true
  log "Repository package installed."
  sudo apt-get update -y >/dev/null 2>&1 &
  spinner_with_runner $! "Updating package lists..."
  apt_with_animation "Installing Graylog DataNode" graylog-datanode
}

configure_graylog_datanode() {
  section "Configuring Graylog DataNode"
  type_echo "Configuring DataNode settings..."
  echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.d/99-graylog-datanode.conf >/dev/null
  log "vm.max_map_count set."
  sudo sysctl --system >/dev/null 2>&1
  log "Sysctl configurations loaded."
  sudo sed -i "/password_secret/c\\password_secret = $(openssl rand -hex 32)" /etc/graylog/datanode/datanode.conf || true
  log "Password secret generated."
  sudo sed -i "/mongodb_uri/c\\mongodb_uri = mongodb://127.0.0.1:27017/graylog" /etc/graylog/datanode/datanode.conf || true
  log "MongoDB URI set."
  # Calculate half of system RAM for opensearch_heap
  total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
  half_ram_mb=$((total_ram_kb / 1024 / 2))
  half_ram_gb=$(( (half_ram_mb + 512) / 1024 ))  # Round to nearest GB
  echo "opensearch_heap = ${half_ram_gb}g" >> /etc/graylog/datanode/datanode.conf
  log "OpenSearch heap set to ${half_ram_gb} GB (half of system RAM)."
  # Bind OpenSearch to localhost
  echo "opensearch_bind_address = 127.0.0.1" >> /etc/graylog/datanode/datanode.conf
  log "OpenSearch bound to localhost."
  sudo systemctl daemon-reload >/dev/null 2>&1
  sleep 2
  log "Daemon reloaded."
  sudo systemctl enable graylog-datanode.service >/dev/null 2>&1
  sleep 2
  log "DataNode service enabled."
  sudo systemctl start graylog-datanode >/dev/null 2>&1
  sleep 2
  log "DataNode service started."
}

install_graylog_server() {
  section "Starting Graylog Server Installer"
  type_echo "Installing Graylog Server..."
  apt_with_animation "Installing Graylog Server" graylog-server
  sudo sed -i "/password_secret/c$(sed -n '/password_secret/{p;q}' /etc/graylog/datanode/datanode.conf)" /etc/graylog/server/server.conf || true
  log "Password secret copied from DataNode."
  sudo sed -i '0,/http_bind_address/{s|.*http_bind_address.*|http_bind_address = 127.0.0.1:9000|}' /etc/graylog/server/server.conf
  log "HTTP bind address set to localhost."
  # Generate self-signed certificates for TLS
  sudo mkdir -p /etc/graylog/certs
  sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/graylog/certs/graylog.key -out /etc/graylog/certs/graylog.crt -subj "/C=GB/ST=London/L=London/O=Graylog/CN=$(hostname)" >/dev/null 2>&1
  sudo chown graylog:graylog /etc/graylog/certs/*
  sudo chmod 600 /etc/graylog/certs/*
  log "Self-signed TLS certificates generated."
  # Enable TLS
  sudo sed -i '/http_enable_tls/c\http_enable_tls = true' /etc/graylog/server/server.conf
  sudo sed -i '/http_tls_cert_file/c\http_tls_cert_file = /etc/graylog/certs/graylog.crt' /etc/graylog/server/server.conf
  sudo sed -i '/http_tls_key_file/c\http_tls_key_file = /etc/graylog/certs/graylog.key' /etc/graylog/server/server.conf
  log "TLS enabled for Graylog web interface."
  type_echo "Enter Password for root: "
  read -sp "" pw && echo
  hash=$(echo -n "$pw" | sha256sum | cut -d' ' -f1)
  sudo sed -i "/^root_password_sha2 =/c\root_password_sha2 = $hash" /etc/graylog/server/server.conf
  log "Root password hashed and set."
  sudo sed -i '/^GRAYLOG_SERVER_JAVA_OPTS="-Xms1g/c\GRAYLOG_SERVER_JAVA_OPTS="-Xms2g -Xmx2g -server -XX:+UseG1GC -XX:-OmitStackTraceInFastThrow"' /etc/default/graylog-server
  log "Java options updated."
  sudo systemctl daemon-reload >/dev/null 2>&1
  sleep 2
  log "Daemon reloaded."
  sudo systemctl enable graylog-server.service >/dev/null 2>&1
  sleep 2
  log "Server service enabled."
  sudo systemctl start graylog-server.service >/dev/null 2>&1
  sleep 5
  log "Server service started."
}

uninstall_everything() {
  section "Uninstalling MongoDB and Graylog"
  type_echo "Initiating complete removal of MongoDB and Graylog components..."

  # Stop and disable services
  type_echo "Stopping and disabling services..."
  for service in graylog-server.service graylog-datanode.service mongod.service; do
    if systemctl is-active --quiet $service; then
      sudo systemctl stop $service >/dev/null 2>&1 &
      spinner_with_runner $! "Stopping $service..."
    fi
    if systemctl is-enabled --quiet $service; then
      sudo systemctl disable $service >/dev/null 2>&1 &
      spinner_with_runner $! "Disabling $service..."
    fi
  done
  log "All services stopped and disabled."

  # Purge packages
  type_echo "Removing installed packages..."
  purge_with_animation "Purging Graylog and MongoDB packages" graylog-server graylog-datanode mongodb-org mongodb-org-*
  log "Packages purged."

  # Remove configuration files, logs, and data
  type_echo "Cleaning up configuration files and data..."
  sudo rm -rf /etc/graylog /var/log/graylog-server /var/log/graylog-datanode /var/lib/mongodb /var/log/mongodb /etc/sysctl.d/99-graylog-datanode.conf /tmp/graylog-repo.deb /etc/graylog/certs >/dev/null 2>&1 &
  spinner_with_runner $! "Removing configuration files, logs, and data..."
  log "Configurations and data removed."

  # Remove repositories
  type_echo "Removing MongoDB and Graylog repositories..."
  sudo rm -f /etc/apt/sources.list.d/mongodb-org-8.0.list /etc/apt/sources.list.d/graylog.list /usr/share/keyrings/mongodb-server-8.0.gpg >/dev/null 2>&1 &
  spinner_with_runner $! "Removing repository configurations..."
  sudo apt-get update -y >/dev/null 2>&1 &
  spinner_with_runner $! "Updating package lists..."
  log "Repositories removed."

  section "Uninstallation Complete"
  type_echo "MongoDB and Graylog have been completely removed."
  echo -e "${CYAN}System Status:${RESET} Clean"
}

main() {
  clear
  ascii_banner
  sleep 1

  if [[ "${1:-}" == "--uninstall" ]]; then
    uninstall_everything
  else
    ensure_prereqs
    add_mongodb_repo
    configure_mongodb
    install_graylog_datanode
    configure_graylog_datanode
    install_graylog_server

    section "Tailing Graylog Server Log"
    type_echo "Displaying recent log entries for verification..."
    tail /var/log/graylog-server/server.log

    section "Installation Complete"
    type_echo "Graylog is alive (if services are up)."
    echo -e "${CYAN}Web UI:${RESET} https://<server-ip>:9000"
    echo -e "${CYAN}Tail logs:${RESET} sudo tail -f /var/log/graylog-server/server.log"
    ifconfig
  fi
}
main "$@"
