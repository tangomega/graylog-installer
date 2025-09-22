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
                                                                                                                                                                                                                                                                                                                 
         Graylog Installer (v1.0)
EOF
}

type_echo() {
  local text="$1"
  local delay="${2:-0.01}"
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
  echo -e "${MAGENTA}${BOLD}>> $1${RESET}"
  echo -e "${CYAN}============================================================${RESET}\n"
}

log() {
  echo -e "${GREEN}[+]${RESET} $1"
}

error() {
  echo -e "${MAGENTA}[ERROR]${RESET} $1" >&2
  exit 1
}

# --- Verification Function ---
verify() {
  local type="$1"
  local target="$2"
  local msg="$3"
  case $type in
    package)
      if dpkg -l "$target" >/dev/null 2>/dev/null; then
        log "$msg"
      else
        error "Failed to verify package: $target is not installed."
      fi
      ;;
    service)
      if systemctl is-active --quiet "$target" && systemctl is-enabled --quiet "$target"; then
        log "$msg"
      else
        error "Failed to verify service: $target is not active or enabled."
      fi
      ;;
    file)
      if [ -f "$target" ]; then
        log "$msg"
      else
        error "Failed to verify file: $target does not exist."
      fi
      ;;
    config)
      if grep -q "$target" "$4"; then
        log "$msg"
      else
        error "Failed to verify configuration: $target not found in $4."
      fi
      ;;
    port)
      if curl -s --connect-timeout 5 "http://127.0.0.1:$target" >/dev/null 2>/dev/null; then
        log "$msg"
      else
        error "Failed to verify port: $target is not accessible."
      fi
      ;;
    firewall)
      if sudo ufw status verbose | grep -q "$target"; then
        log "$msg"
      else
        error "Failed to verify firewall rule: $target not found in UFW status."
      fi
      ;;
    *)
      error "Invalid verification type: $type"
      ;;
  esac
}

# --- Stick Figure Progress Bar ---
spinner_with_runner() {
  local pid=$1
  local msg=$2
  local delay=0.1
  local frames="🏃 🏃‍♂️ 🏃‍♀️"
  local width=30
  local progress=0

  echo -ne "$msg\n"

  while kill -0 $pid 2>/dev/null; do
    local filled=$((progress % (width + 1)))
    local empty=$((width - filled))
    local bar=$(printf "%0.s#" $(seq 1 $filled))
    local space=$(printf "%0.s " $(seq 1 $empty))
    local frame_count=$(echo "$frames" | wc -w)
    local frame_index=$((progress % frame_count + 1))
    local frame=$(echo "$frames" | awk "{print \$${frame_index}}")

    printf "\r[%s%s] %s %s" "$bar" "$space" "$frame" "$msg"
    sleep $delay
    progress=$((progress + 1))
  done

  printf "\r[%s] ✅ %s\n" "$(printf "%0.s#" $(seq 1 $width))" "$msg"
}

# --- APT Install Wrapper ---
apt_with_animation() {
  local msg=$1; shift
  sudo apt-get update -y >/dev/null 2>/dev/null &
  spinner_with_runner $! "Updating package sources..."
  wait $! || true

  sudo apt-get install -y "$@" >/dev/null 2>/dev/null &
  spinner_with_runner $! "$msg"
  wait $! || true
  for pkg in "$@"; do
    verify package "$pkg" "$pkg installed successfully."
  done
}

# --- APT Purge Wrapper ---
purge_with_animation() {
  local msg=$1; shift
  sudo apt-get purge -y "$@" >/dev/null 2>/dev/null &
  spinner_with_runner $! "$msg"
  wait $! || true
  for pkg in "$@"; do
    if dpkg -l "$pkg" >/dev/null 2>/dev/null; then
      error "Failed to purge package: $pkg is still installed."
    else
      log "$pkg removed successfully."
    fi
  done
  sudo apt-get autoremove -y >/dev/null 2>/dev/null &
  spinner_with_runner $! "Removing unused dependencies..."
  wait $! || true
}

ensure_prereqs() {
  section "Installing Essential Packages"
  type_echo "Installing prerequisite packages..."
  apt_with_animation "Installing gnupg, curl, lsb-release" gnupg curl lsb-release net-tools
}

add_mongodb_repo() {
  section "Installing MongoDB"
  type_echo "Configuring MongoDB repository..."
  curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor >/dev/null 2>/dev/null &
  spinner_with_runner $! "Adding MongoDB GPG key..."
  verify file "/usr/share/keyrings/mongodb-server-8.0.gpg" "MongoDB GPG key added."
  echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list >/dev/null
  verify file "/etc/apt/sources.list.d/mongodb-org-8.0.list" "MongoDB repository configured."
  sudo apt-get update -y >/dev/null 2>/dev/null &
  spinner_with_runner $! "Updating package lists..."
  apt_with_animation "Installing MongoDB" mongodb-org
  sudo apt-mark hold mongodb-org >/dev/null || true
  log "MongoDB version locked."
}

configure_mongodb() {
  section "Configuring MongoDB"
  type_echo "Configuring MongoDB settings..."
  sudo sed -i '/bindIp/c\  bindIp: 127.0.0.1' /etc/mongod.conf
  verify config "bindIp: 127.0.0.1" "MongoDB bound to localhost." /etc/mongod.conf
  sudo systemctl daemon-reload >/dev/null 2>/dev/null &
  spinner_with_runner $! "Reloading system daemon..."
  log "System daemon reloaded."
  sudo systemctl enable mongod.service >/dev/null 2>/dev/null &
  spinner_with_runner $! "Enabling MongoDB service..."
  sudo systemctl start mongod.service >/dev/null 2>/dev/null &
  spinner_with_runner $! "Starting MongoDB service..."
  verify service mongod "MongoDB service active and enabled."
}

install_graylog_datanode() {
  section "Installing Graylog DataNode"
  type_echo "Installing Graylog DataNode components..."
  apt_with_animation "Installing required dependencies" gnupg curl wget apt-transport-https openjdk-17-jre-headless
  wget https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb -O /tmp/graylog-repo.deb >/dev/null 2>/dev/null &
  spinner_with_runner $! "Downloading Graylog repository package..."
  verify file "/tmp/graylog-repo.deb" "Graylog repository package downloaded."
  sudo dpkg -i /tmp/graylog-repo.deb >/dev/null 2>/dev/null || true
  verify file "/etc/apt/sources.list.d/graylog.list" "Graylog repository package installed."
  sudo apt-get update -y >/dev/null 2>/dev/null &
  spinner_with_runner $! "Updating package lists..."
  apt_with_animation "Installing Graylog DataNode" graylog-datanode
}

configure_graylog_datanode() {
  section "Configuring Graylog DataNode"
  type_echo "Applying Graylog DataNode configurations..."
  echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.d/99-graylog-datanode.conf >/dev/null
  verify config "vm.max_map_count=262144" "System parameter vm.max_map_count configured." /etc/sysctl.d/99-graylog-datanode.conf
  sudo sysctl --system >/dev/null 2>/dev/null &
  spinner_with_runner $! "Applying system parameters..."
  log "System parameters applied."
  sudo sed -i "/password_secret/c\\password_secret = $(openssl rand -hex 32)" /etc/graylog/datanode/datanode.conf || true
  verify config "password_secret" "Password secret generated." /etc/graylog/datanode/datanode.conf
  sudo sed -i "/mongodb_uri/c\\mongodb_uri = mongodb://127.0.0.1:27017/graylog" /etc/graylog/datanode/datanode.conf || true
  verify config "mongodb_uri = mongodb://127.0.0.1:27017/graylog" "MongoDB URI configured." /etc/graylog/datanode/datanode.conf
  total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
  half_ram_mb=$((total_ram_kb / 1024 / 2))
  half_ram_gb=$(( (half_ram_mb + 512) / 1024 ))
  echo "opensearch_heap = ${half_ram_gb}g" >> /etc/graylog/datanode/datanode.conf
  verify config "opensearch_heap = ${half_ram_gb}g" "OpenSearch heap set to ${half_ram_gb} GB." /etc/graylog/datanode/datanode.conf
  sudo systemctl daemon-reload >/dev/null 2>/dev/null &
  spinner_with_runner $! "Reloading system daemon..."
  log "System daemon reloaded."
  sudo systemctl enable graylog-datanode.service >/dev/null 2>/dev/null &
  spinner_with_runner $! "Enabling Graylog DataNode service..."
  sudo systemctl start graylog-datanode >/dev/null 2>/dev/null &
  spinner_with_runner $! "Starting Graylog DataNode service..."
  verify service graylog-datanode "Graylog DataNode service active and enabled."
}

install_graylog_server() {
  section "Installing Graylog Server"
  type_echo "Installing Graylog Server components..."
  apt_with_animation "Installing Graylog Server" graylog-server
  sudo sed -i "/password_secret/c$(sed -n '/password_secret/{p;q}' /etc/graylog/datanode/datanode.conf)" /etc/graylog/server/server.conf || true
  verify config "password_secret" "Password secret synchronized with DataNode." /etc/graylog/server/server.conf
  sudo sed -i '0,/http_bind_address/{s|.*http_bind_address.*|http_bind_address = 0.0.0.0:9000|}' /etc/graylog/server/server.conf
  verify config "http_bind_address = 0.0.0.0:9000" "HTTP bind address set to port 9000." /etc/graylog/server/server.conf
  type_echo "Enter password for Graylog administrator: "
  read -sp "" pw && echo
  hash=$(echo -n "$pw" | sha256sum | cut -d' ' -f1)
  sudo sed -i "/^root_password_sha2 =/c\root_password_sha2 = $hash" /etc/graylog/server/server.conf
  verify config "root_password_sha2" "Administrator password configured." /etc/graylog/server/server.conf
  sudo sed -i '/^GRAYLOG_SERVER_JAVA_OPTS="-Xms1g/c\GRAYLOG_SERVER_JAVA_OPTS="-Xms2g -Xmx2g -server -XX:+UseG1GC -XX:-OmitStackTraceInFastThrow"' /etc/default/graylog-server
  verify config "GRAYLOG_SERVER_JAVA_OPTS=\"-Xms2g -Xmx2g" "Java runtime options configured." /etc/default/graylog-server
  sudo systemctl daemon-reload >/dev/null 2>/dev/null &
  spinner_with_runner $! "Reloading system daemon..."
  log "System daemon reloaded."
  sudo systemctl enable graylog-server.service >/dev/null 2>/dev/null &
  spinner_with_runner $! "Enabling Graylog Server service..."
  sudo systemctl start graylog-server.service >/dev/null 2>/dev/null &
  spinner_with_runner $! "Starting Graylog Server service..."
  verify service graylog-server "Graylog Server service active and enabled."
}

configure_firewall() {
  section "Configuring Firewall"
  type_echo "Configuring UFW firewall..."

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

  type_echo "Detecting LAN subnet..."
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
        log "Detected LAN subnet: $lan_subnet"
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

  apt_with_animation "Installing UFW" ufw
  sudo ufw --force enable >/dev/null 2>/dev/null &
  spinner_with_runner $! "Enabling firewall..."
  verify firewall "Status: active" "Firewall enabled."
  sudo ufw default deny incoming >/dev/null 2>/dev/null &
  spinner_with_runner $! "Setting default firewall policy to deny incoming traffic..."
  verify firewall "deny" "Default firewall policy configured."
  sudo ufw allow from "$lan_subnet" to any port 22 proto tcp >/dev/null 2>/dev/null &
  spinner_with_runner $! "Allowing SSH access from LAN ($lan_subnet)..."
  verify firewall "22/tcp.*$lan_subnet" "SSH access configured."
  sudo ufw allow from "$lan_subnet" to any port 9000 proto tcp >/dev/null 2>/dev/null &
  spinner_with_runner $! "Allowing Graylog HTTP access from LAN ($lan_subnet)..."
  verify firewall "9000/tcp.*$lan_subnet" "Graylog HTTP access configured."
  sudo ufw allow from "$lan_subnet" to any port 9200 proto tcp >/dev/null 2>/dev/null &
  spinner_with_runner $! "Allowing OpenSearch HTTP access from LAN ($lan_subnet)..."
  verify firewall "9200/tcp.*$lan_subnet" "OpenSearch HTTP access configured."
  sudo ufw allow from "$lan_subnet" to any port 9300 proto tcp >/dev/null 2>/dev/null &
  spinner_with_runner $! "Allowing OpenSearch node communication from LAN ($lan_subnet)..."
  verify firewall "9300/tcp.*$lan_subnet" "OpenSearch node communication configured."
  sudo ufw allow from "$lan_subnet" to any port 2514 proto udp >/dev/null 2>/dev/null &
  spinner_with_runner $! "Allowing Syslog input from LAN ($lan_subnet)..."
  verify firewall "2514/udp.*$lan_subnet" "Syslog input access configured."
  sudo ufw allow from "$lan_subnet" to any port 12201 proto tcp >/dev/null 2>/dev/null &
  spinner_with_runner $! "Allowing GELF input from LAN ($lan_subnet)..."
  verify firewall "12201/tcp.*$lan_subnet" "GELF input access configured."
  sudo ufw --force enable >/dev/null 2>/dev/null &
  sudo ufw status >/dev/null 2>/dev/null &
  spinner_with_runner $! "Verifying firewall configuration..."
  log "Firewall configuration completed."
}

uninstall_everything() {
  section "Uninstalling MongoDB and Graylog"
  type_echo "Removing MongoDB and Graylog components..."

  type_echo "Stopping and disabling services..."
  for service in graylog-server.service graylog-datanode.service mongod.service; do
    if systemctl is-active --quiet $service; then
      sudo systemctl stop $service >/dev/null 2>/dev/null &
      spinner_with_runner $! "Stopping $service..."
      if systemctl is-active --quiet $service; then
        error "Failed to stop service: $service is still running."
      else
        log "$service stopped."
      fi
    fi
    if systemctl is-enabled --quiet $service; then
      sudo systemctl disable $service >/dev/null 2>/dev/null &
      spinner_with_runner $! "Disabling $service..."
      if systemctl is-enabled --quiet $service; then
        error "Failed to disable service: $service is still enabled."
      else
        log "$service disabled."
      fi
    fi
  done
  log "All services stopped and disabled."

  type_echo "Resetting firewall configuration..."
  sudo ufw --force reset >/dev/null 2>/dev/null &
  spinner_with_runner $! "Resetting firewall rules..."
  if sudo ufw status | grep -q "Status: active"; then
    error "Failed to reset firewall: UFW is still active."
  else
    log "Firewall rules reset."
  fi

  type_echo "Removing installed packages..."
  purge_with_animation "Removing Graylog and MongoDB packages" graylog-server graylog-datanode mongodb-org mongodb-org-*

  type_echo "Removing configuration files and data..."
  sudo rm -rf /etc/graylog /var/log/graylog-server /var/log/graylog-datanode /var/lib/mongodb /var/log/mongodb /etc/sysctl.d/99-graylog-datanode.conf /tmp/graylog-repo.deb >/dev/null 2>/dev/null &
  spinner_with_runner $! "Removing configuration files, logs, and data..."
  for dir in /etc/graylog /var/log/graylog-server /var/log/graylog-datanode /var/lib/mongodb /var/log/mongodb /etc/sysctl.d/99-graylog-datanode.conf /tmp/graylog-repo.deb; do
    if [ -e "$dir" ]; then
      error "Failed to remove: $dir still exists."
    fi
  done
  log "Configurations and data removed."

  type_echo "Removing MongoDB and Graylog repositories..."
  sudo rm -f /etc/apt/sources.list.d/mongodb-org-8.0.list /etc/apt/sources.list.d/graylog.list /usr/share/keyrings/mongodb-server-8.0.gpg >/dev/null 2>/dev/null &
  spinner_with_runner $! "Removing repository configurations..."
  for file in /etc/apt/sources.list.d/mongodb-org-8.0.list /etc/apt/sources.list.d/graylog.list /usr/share/keyrings/mongodb-server-8.0.gpg; do
    if [ -e "$file" ]; then
      error "Failed to remove: $file still exists."
    fi
  done
  sudo apt-get update -y >/dev/null 2>/dev/null &
  spinner_with_runner $! "Updating package lists..."
  log "Repositories removed."

  section "Uninstallation Complete"
  type_echo "MongoDB and Graylog removal completed."
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
    configure_firewall

    section "Verifying Network Connectivity"
    type_echo "Checking Graylog web interface and OpenSearch accessibility..."
    verify port 9000 "Graylog web interface accessible on port 9000."

    section "Reviewing Graylog Server Logs"
    type_echo "Displaying recent log entries for verification..."
    tail /var/log/graylog-server/server.log

    section "Installation Complete"
    type_echo "Graylog installation completed successfully."
    echo -e "${CYAN}Web UI:${RESET} http://<server-ip>:9000"
    echo -e "${CYAN}Log Monitoring:${RESET} sudo tail -f /var/log/graylog-server/server.log"
    echo -e "${CYAN}Note:${RESET} Configure Syslog (port 2514, UDP) and GELF (port 12201, TCP) inputs via the Graylog web interface."
    ip addr show
  fi
}
main "$@"
