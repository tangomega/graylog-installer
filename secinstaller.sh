```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Colors & Effects
GREEN="\033[0;32m"
CYAN="\033[0;36m"
MAGENTA="\033[0;35m"
BLUE="\033[0;34m"
YELLOW="\033[0;33m"
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
  local delay="${2:-0.02}"
  local i=0
  while [ $i -lt ${#text} ]; do
    printf "%s" "${text:$i:1}"
    sleep "$delay"
    i=$((i + 1))
  done
  printf "\n"
}

section() {
  echo -e "\n${CYAN}============================================================${RESET}"
  type_echo "${MAGENTA}${BOLD} $1 ${RESET}"
  echo -e "${CYAN}============================================================${RESET}\n"
}

log() {
  echo -e "${GREEN}✔${RESET} $1"
}

# --- Enhanced Progress Bar ---
spinner_with_runner() {
  local pid=$1
  local msg=$2
  local delay=0.1
  local frames=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏" "🏃")
  local width=30
  local progress=0
  local total_steps=100

  echo -ne "${BLUE}${msg}${RESET}\n"

  while kill -0 $pid 2>/dev/null; do
    local percent=$((progress * 100 / total_steps))
    local filled=$((progress * width / total_steps))
    local empty=$((width - filled))
    local bar=$(printf "%0.s█" $(seq 1 $filled))
    local space=$(printf "%0.s " $(seq 1 $empty))
    local frame=${frames[$((progress % ${#frames[@]}))]}

    printf "\r${BLUE}[%s%s] %3d%% %s %s${RESET}" "$bar" "$space" "$percent" "$frame" "$msg"
    sleep $delay
    progress=$((progress + 1))
    [ $progress -gt $total_steps ] && progress=0
  done

  printf "\r${GREEN}[%s] 100%% ✅ %s${RESET}\n" "$(printf "%0.s█" $(seq 1 $width))" "$msg"
}

# --- APT Install Wrapper ---
apt_with_animation() {
  local msg=$1; shift
  sudo apt-get update -y >/dev/null 2>&1 &
  spinner_with_runner $! "Updating package sources"
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
  spinner_with_runner $! "Removing unused dependencies"
  wait $! || true
}

ensure_prereqs() {
  section "Installing Essential Packages"
  type_echo "Installing prerequisite packages..."
  apt_with_animation "Installing core dependencies" gnupg curl lsb-release net-tools
  log "Core dependencies installed."
}

add_mongodb_repo() {
  section "Installing MongoDB"
  type_echo "Configuring MongoDB repository..."
  curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor >/dev/null 2>&1 &
  spinner_with_runner $! "Adding MongoDB GPG key"
  echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list >/dev/null
  log "MongoDB repository configured."
  sudo apt-get update -y >/dev/null 2>&1 &
  spinner_with_runner $! "Updating package lists"
  apt_with_animation "Installing MongoDB" mongodb-org
  sudo apt-mark hold mongodb-org >/dev/null || true
  log "MongoDB installation completed."
}

configure_mongodb() {
  section "Configuring MongoDB"
  type_echo "Applying MongoDB configurations..."
  sudo sed -i '/bindIp/c\  bindIp: 127.0.0.1' /etc/mongod.conf
  log "MongoDB bound to localhost."
  sudo systemctl daemon-reload >/dev/null 2>&1 &
  spinner_with_runner $! "Reloading system daemon"
  sudo systemctl enable mongod.service >/dev/null 2>&1 &
  spinner_with_runner $! "Enabling MongoDB service"
  sudo systemctl start mongod.service >/dev/null 2>&1 &
  spinner_with_runner $! "Starting MongoDB service"
  log "MongoDB configuration completed."
}

install_graylog_datanode() {
  section "Installing Graylog DataNode"
  type_echo "Installing Graylog DataNode components..."
  apt_with_animation "Installing required dependencies" gnupg curl wget apt-transport-https openjdk-17-jre-headless
  wget https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb -O /tmp/graylog-repo.deb >/dev/null 2>&1 &
  spinner_with_runner $! "Downloading Graylog repository package"
  sudo dpkg -i /tmp/graylog-repo.deb >/dev/null 2>&1 || true
  log "Graylog repository configured."
  sudo apt-get update -y >/dev/null 2>&1 &
  spinner_with_runner $! "Updating package lists"
  apt_with_animation "Installing Graylog DataNode" graylog-datanode
  log "Graylog DataNode installation completed."
}

configure_graylog_datanode() {
  section "Configuring Graylog DataNode"
  type_echo "Applying Graylog DataNode settings..."
  echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.d/99-graylog-datanode.conf >/dev/null
  sudo sysctl --system >/dev/null 2>&1 &
  spinner_with_runner $! "Configuring system parameters"
  sudo sed -i "/password_secret/c\\password_secret = $(openssl rand -hex 32)" /etc/graylog/datanode/datanode.conf || true
  log "Password secret generated."
  sudo sed -i "/mongodb_uri/c\\mongodb_uri = mongodb://127.0.0.1:27017/graylog" /etc/graylog/datanode/datanode.conf || true
  log "MongoDB URI configured."
  total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
  half_ram_mb=$((total_ram_kb / 1024 / 2))
  half_ram_gb=$(( (half_ram_mb + 512) / 1024 ))
  echo "opensearch_heap = ${half_ram_gb}g" >> /etc/graylog/datanode/datanode.conf
  log "OpenSearch heap set to ${half_ram_gb} GB."
  sudo systemctl daemon-reload >/dev/null 2>&1 &
  spinner_with_runner $! "Reloading system daemon"
  sudo systemctl enable graylog-datanode.service >/dev/null 2>&1 &
  spinner_with_runner $! "Enabling Graylog DataNode service"
  sudo systemctl start graylog-datanode >/dev/null 2>&1 &
  spinner_with_runner $! "Starting Graylog DataNode service"
  log "Graylog DataNode configuration completed."
}

install_graylog_server() {
  section "Installing Graylog Server"
  type_echo "Installing Graylog Server components..."
  apt_with_animation "Installing Graylog Server" graylog-server
  sudo sed -i "/password_secret/c$(sed -n '/password_secret/{p;q}' /etc/graylog/datanode/datanode.conf)" /etc/graylog/server/server.conf || true
  log "Password secret synchronized."
  sudo sed -i '0,/http_bind_address/{s|.*http_bind_address.*|http_bind_address = 0.0.0.0:9000|}' /etc/graylog/server/server.conf
  log "HTTP bind address configured."
  type_echo "Enter password for Graylog administrator: "
  read -sp "" pw && echo
  hash=$(echo -n "$pw" | sha256sum | cut -d' ' -f1)
  sudo sed -i "/^root_password_sha2 =/c\root_password_sha2 = $hash" /etc/graylog/server/server.conf
  log "Administrator password configured."
  sudo sed -i '/^GRAYLOG_SERVER_JAVA_OPTS="-Xms1g/c\GRAYLOG_SERVER_JAVA_OPTS="-Xms2g -Xmx2g -server -XX:+UseG1GC -XX:-OmitStackTraceInFastThrow"' /etc/default/graylog-server
  log "Java runtime options configured."
  sudo systemctl daemon-reload >/dev/null 2>&1 &
  spinner_with_runner $! "Reloading system daemon"
  sudo systemctl enable graylog-server.service >/dev/null 2>&1 &
  spinner_with_runner $! "Enabling Graylog Server service"
  sudo systemctl start graylog-server.service >/dev/null 2>&1 &
  spinner_with_runner $! "Starting Graylog Server service"
  log "Graylog Server installation completed."
}

configure_firewall() {
  section "Configuring Firewall"
  type_echo "Setting up UFW firewall..."

  get_subnet() {
    local ip=$1
    local mask=$2
    IFS='.' read -r i1 i2 i3 i4 <<< "$ip"
    IFS='.' read -r m1 m2 m3 m4 <<< "$mask"
    local n1=$((i1 & m1))
    local n2=$((i2 & m2))
    local n3=$((i3 & m3))
    local n4=$((i4 & m4))
    local prefix=0
    for byte in $m1 $m2 $m3 $m4; do
      while [ $byte -gt 0 ]; do
        prefix=$((prefix + (byte & 1)))
        byte=$((byte >> 1))
      done
    done
    echo "$n1.$n2.$n3.$n4/$prefix"
  }

  type_echo "Detecting network configuration..."
  local interface
  local ip_info
  local lan_subnet="192.168.1.0/24"

  interface=$(ip link | awk -F: '$0 !~ "lo|docker|br-|^[^0-9]"{print $2; getline}' | head -n 1 | xargs)
  if [ -n "$interface" ]; then
    ip_info=$(ip addr show "$interface" | grep -w inet | awk '{print $2}' | head -n 1)
    if [ -n "$ip_info" ]; then
      local ip_address=$(echo "$ip_info" | cut -d'/' -f1)
      local cidr_prefix=$(echo "$ip_info" | cut -d'/' -f2)
      local netmask
      case $cidr_prefix in
        24) netmask="255.255.255.0" ;;
        16) netmask="255.255.0.0" ;;
        8) netmask="255.0.0.0" ;;
        *) netmask=$(ipcalc "$ip_info" | grep Netmask | awk '{print $2}') ;;
      esac
      if [ -n "$netmask" ]; then
        lan_subnet=$(get_subnet "$ip_address" "$netmask")
        log "Network subnet detected: $lan_subnet"
      else
        log "Unable to calculate subnet, using default: $lan_subnet"
      fi
    else
      log "No IP address found for interface $interface, using default subnet: $lan_subnet"
    fi
  else
    log "No network interface found, using default subnet: $lan_subnet"
  fi

  lan_subnet="${LAN_SUBNET:-$lan_subnet}"

  apt_with_animation "Installing UFW firewall" ufw
  sudo ufw default deny incoming >/dev/null 2>&1 &
  spinner_with_runner $! "Setting default firewall policy"
  sudo ufw allow from "$lan_subnet" to any port 22 proto tcp >/dev/null 2>&1 &
  spinner_with_runner $! "Configuring SSH access ($lan_subnet)"
  sudo ufw allow from "$lan_subnet" to any port 9000 proto tcp >/dev/null 2>&1 &
  spinner_with_runner $! "Configuring Graylog HTTP access ($lan_subnet)"
  sudo ufw allow from "$lan_subnet" to any port 9200 proto tcp >/dev/null 2>&1 &
  spinner_with_runner $! "Configuring OpenSearch HTTP access ($lan_subnet)"
  sudo ufw allow from "$lan_subnet" to any port 9300 proto tcp >/dev/null 2>&1 &
  spinner_with_runner $! "Configuring OpenSearch node communication ($lan_subnet)"
  sudo ufw allow from "$lan_subnet" to any port 514 proto udp >/dev/null 2>&1 &
  spinner_with_runner $! "Configuring Syslog input ($lan_subnet)"
  sudo ufw allow from "$lan_subnet" to any port 12201 proto tcp >/dev/null 2>&1 &
  spinner_with_runner $! "Configuring GELF input ($lan_subnet)"
  sudo ufw --force enable >/dev/null 2>&1 &
  spinner_with_runner $! "Activating firewall"
  sudo ufw status >/dev/null 2>&1 &
  spinner_with_runner $! "Verifying firewall configuration"
  log "Firewall configuration completed."
}

uninstall_everything() {
  section "Uninstalling MongoDB and Graylog"
  type_echo "Removing MongoDB and Graylog components..."

  type_echo "Stopping and disabling services..."
  for service in graylog-server.service graylog-datanode.service mongod.service; do
    if systemctl is-active --quiet $service; then
      sudo systemctl stop $service >/dev/null 2>&1 &
      spinner_with_runner $! "Stopping $service"
    fi
    if systemctl is-enabled --quiet $service; then
      sudo systemctl disable $service >/dev/null 2>&1 &
      spinner_with_runner $! "Disabling $service"
    fi
  done
  log "Services stopped and disabled."

  type_echo "Resetting firewall configuration..."
  sudo ufw --force reset >/dev/null 2>&1 &
  spinner_with_runner $! "Resetting firewall rules"
  log "Firewall configuration reset."

  type_echo "Removing installed packages..."
  purge_with_animation "Removing Graylog and MongoDB packages" graylog-server graylog-datanode mongodb-org mongodb-org-*
  log "Packages removed."

  type_echo "Cleaning up configuration and data..."
  sudo rm -rf /etc/graylog /var/log/graylog-server /var/log/graylog-datanode /var/lib/mongodb /var/log/mongodb /etc/sysctl.d/99-graylog-datanode.conf /tmp/graylog-repo.deb >/dev/null 2>&1 &
  spinner_with_runner $! "Removing configuration and data"
  log "Configuration and data removed."

  type_echo "Removing repositories..."
  sudo rm -f /etc/apt/sources.list.d/mongodb-org-8.0.list /etc/apt/sources.list.d/graylog.list /usr/share/keyrings/mongodb-server-8.0.gpg >/dev/null 2>&1 &
  spinner_with_runner $! "Removing repository configurations"
  sudo apt-get update -y >/dev/null 2>&1 &
  spinner_with_runner $! "Updating package lists"
  log "Repositories removed."

  section "Uninstallation Complete"
  type_echo "MongoDB and Graylog successfully removed."
  echo -e "${CYAN}System Status:${RESET} Clean"
  echo -e "${GREEN}✔ Uninstallation completed successfully.${RESET}"
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
    configure_firewall

    section "Reviewing Graylog Server Logs"
    type_echo "Displaying recent log entries for verification..."
    tail /var/log/graylog-server/server.log

    section "Installation Complete"
    type_echo "MongoDB and Graylog installation completed successfully."
    echo -e "${CYAN}Web Interface:${RESET} ${BOLD}http://<server-ip>:9000${RESET}"
    echo -e "${CYAN}Log Monitoring:${RESET} ${BOLD}sudo tail -f /var/log/graylog-server/server.log${RESET}"
    echo -e "${CYAN}Next Steps:${RESET} Configure Syslog (port 514/UDP) and GELF (port 12201/TCP) inputs in the Graylog web interface."
    echo -e "${CYAN}Network Details:${RESET}"
    ip addr show
    echo -e "${GREEN}✔ Installation completed successfully. Ready to monitor your logs!${RESET}"
  fi
}
main "$@"
```
