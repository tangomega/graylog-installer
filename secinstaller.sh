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
  type_echo "[HACKER] Ensuring prerequisites are present..."
  apt_with_animation "Installing gnupg, curl, lsb-release" gnupg curl lsb-release net-tools
}

add_mongodb_repo() {
  section "Installing MongoDB"
  type_echo "[HACKER] Adding official MongoDB APT repo..."
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
  type_echo "[HACKER] Configuring MongoDB for operation..."
  sudo sed -i '/bindIp/c\  bindIp: 127.0.0.1' /etc/mongod.conf
  log "MongoDB bound to localhost."
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
  type_echo "[HACKER] Installing Graylog DataNode components..."
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
  type_echo "[HACKER] Configuring DataNode settings..."
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
  type_echo "[HACKER] Installing Graylog Server..."
  apt_with_animation "Installing Graylog Server" graylog-server
  sudo sed -i "/password_secret/c$(sed -n '/password_secret/{p;q}' /etc/graylog/datanode/datanode.conf)" /etc/graylog/server/server.conf || true
  log "Password secret copied from DataNode."
  sudo sed -i '0,/http_bind_address/{s|.*http_bind_address.*|http_bind_address = 0.0.0.0:9000|}' /etc/graylog/server/server.conf
  log "HTTP bind address set."
  type_echo "[HACKER] Enter Password for root: "
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

configure_tls() {
  section "Configuring TLS/SSL Encryption"
  type_echo "[HACKER] Setting up TLS/SSL for secure communication..."

  # Create directory for certificates
  sudo mkdir -p /etc/graylog/certs >/dev/null 2>&1
  log "Certificate directory created."

  # Generate self-signed certificate for Graylog and OpenSearch
  type_echo "[HACKER] Generating self-signed certificate..."
  sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/graylog/certs/graylog.key \
    -out /etc/graylog/certs/graylog.crt \
    -subj "/C=US/ST=State/L=City/O=Graylog/OU=IT/CN=$(hostname)" >/dev/null 2>&1 &
  spinner_with_runner $! "Generating TLS certificate and key..."
  log "Self-signed certificate generated."

  # Set permissions for certificate files
  sudo chown graylog:graylog /etc/graylog/certs/graylog.{crt,key} >/dev/null 2>&1
  sudo chmod 600 /etc/graylog/certs/graylog.{crt,key} >/dev/null 2>&1
  log "Certificate permissions set."

  # Configure Graylog for HTTPS
  type_echo "[HACKER] Enabling HTTPS for Graylog web interface..."
  sudo sed -i '/http_bind_address/c\http_bind_address = 0.0.0.0:9443' /etc/graylog/server/server.conf
  echo "http_enable_tls = true" | sudo tee -a /etc/graylog/server/server.conf >/dev/null
  echo "http_tls_cert_file = /etc/graylog/certs/graylog.crt" | sudo tee -a /etc/graylog/server/server.conf >/dev/null
  echo "http_tls_key_file = /etc/graylog/certs/graylog.key" | sudo tee -a /etc/graylog/server/server.conf >/dev/null
  log "Graylog configured for HTTPS on port 9443."

  # Configure OpenSearch for TLS
  type_echo "[HACKER] Configuring TLS for OpenSearch..."
  sudo cp /etc/graylog/certs/graylog.{crt,key} /etc/graylog/datanode/ >/dev/null 2>&1
  sudo chown opensearch:opensearch /etc/graylog/datanode/graylog.{crt,key} >/dev/null 2>&1
  sudo chmod 600 /etc/graylog/datanode/graylog.{crt,key} >/dev/null 2>&1
  {
    echo "plugins.security.ssl.http.enabled: true"
    echo "plugins.security.ssl.http.pemcert_filepath: /etc/graylog/datanode/graylog.crt"
    echo "plugins.security.ssl.http.pemkey_filepath: /etc/graylog/datanode/graylog.key"
    echo "plugins.security.ssl.transport.enabled: true"
    echo "plugins.security.ssl.transport.pemcert_filepath: /etc/graylog/datanode/graylog.crt"
    echo "plugins.security.ssl.transport.pemkey_filepath: /etc/graylog/datanode/graylog.key"
  } | sudo tee -a /etc/graylog/datanode/opensearch.yml >/dev/null
  log "OpenSearch configured for TLS on ports 9200 and 9300."

  # Note about input configuration
  type_echo "[HACKER] TLS for inputs (Syslog, GELF) must be configured via Graylog web interface..."
  log "Use /etc/graylog/certs/graylog.crt for Syslog TLS (port 6514) and GELF TLS (port 12201)."

  # Restart services to apply TLS settings
  sudo systemctl restart graylog-server >/dev/null 2>&1 &
  spinner_with_runner $! "Restarting Graylog server for TLS..."
  sudo systemctl restart graylog-datanode >/dev/null 2>&1 &
  spinner_with_runner $! "Restarting Graylog DataNode for TLS..."
  log "Services restarted with TLS enabled."
}

configure_firewall() {
  section "Configuring Firewall"
  type_echo "[HACKER] Securing server with UFW firewall..."

  # Function to calculate subnet from IP and netmask
  get_subnet() {
    local ip=$1
    local mask=$2
    IFS='.' read -r i1 i2 i3 i4 <<< "$ip"
    IFS='.' read -r m1 m2 m3 m4 <<< "$mask"
    # Calculate network address
    local n1=$((i1 & m1))
    local n2=$((i2 & m2))
    local n3=$((i3 & m3))
    local n4=$((i4 & m4))
    # Calculate CIDR prefix from netmask
    local prefix=0
    for byte in $m1 $m2 $m3 $m4; do
      while [ $byte -gt 0 ]; do
        prefix=$((prefix + (byte & 1)))
        byte=$((byte >> 1))
      done
    done
    echo "$n1.$n2.$n3.$n4/$prefix"
  }

  # Detect primary network interface and subnet
  type_echo "[HACKER] Detecting LAN subnet..."
  local interface
  local ip_info
  local lan_subnet="192.168.1.0/24"  # Default fallback

  # Find the first non-loopback interface with an IP address
  interface=$(ip link | awk -F: '$0 !~ "lo|docker|br-|^[^0-9]"{print $2; getline}' | head -n 1 | xargs)
  if [ -n "$interface" ]; then
    ip_info=$(ip addr show "$interface" | grep -w inet | awk '{print $2}' | head -n 1)
    if [ -n "$ip_info" ]; then
      local ip_address=$(echo "$ip_info" | cut -d'/' -f1)
      local cidr_prefix=$(echo "$ip_info" | cut -d'/' -f2)
      # Convert CIDR prefix to netmask
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
        log "Failed to calculate subnet, using default: $lan_subnet"
      fi
    else
      log "No IP address found for interface $interface, using default subnet: $lan_subnet"
    fi
  else
    log "No network interface found, using default subnet: $lan_subnet"
  fi

  # Allow override with LAN_SUBNET environment variable
  lan_subnet="${LAN_SUBNET:-$lan_subnet}"

  # Install UFW
  apt_with_animation "Installing ufw" ufw

  # Set default policy to deny all incoming traffic
  sudo ufw default deny incoming >/dev/null 2>&1 &
  spinner_with_runner $! "Setting default firewall policy to deny incoming..."
  log "Default policy set to deny incoming."

  # Allow SSH (port 22) from LAN
  sudo ufw allow from "$lan_subnet" to any port 22 proto tcp >/dev/null 2>&1 &
  spinner_with_runner $! "Allowing SSH from LAN ($lan_subnet)..."
  log "SSH access allowed from LAN."

  # Allow Graylog web interface and API (port 9443 for HTTPS) from LAN
  sudo ufw allow from "$lan_subnet" to any port 9443 proto tcp >/dev/null 2>&1 &
  spinner_with_runner $! "Allowing Graylog HTTPS from LAN ($lan_subnet)..."
  log "Graylog HTTPS access allowed from LAN."

  # Allow OpenSearch HTTP (port 9200) from LAN
  sudo ufw allow from "$lan_subnet" to any port 9200 proto tcp >/dev/null 2>&1 &
  spinner_with_runner $! "Allowing OpenSearch HTTP from LAN ($lan_subnet)..."
  log "OpenSearch HTTP access allowed from LAN."

  # Allow OpenSearch node communication (port 9300) from LAN
  sudo ufw allow from "$lan_subnet" to any port 9300 proto tcp >/dev/null 2>&1 &
  spinner_with_runner $! "Allowing OpenSearch node communication from LAN ($lan_subnet)..."
  log "OpenSearch node communication allowed from LAN."

  # Allow Graylog Syslog TLS input (port 6514, TCP) from LAN
  sudo ufw allow from "$lan_subnet" to any port 6514 proto tcp >/dev/null 2>&1 &
  spinner_with_runner $! "Allowing Syslog TLS input from LAN ($lan_subnet)..."
  log "Syslog TLS input access allowed from LAN."

  # Allow Graylog GELF TLS input (port 12201, TCP) from LAN
  sudo ufw allow from "$lan_subnet" to any port 12201 proto tcp >/dev/null 2>&1 &
  spinner_with_runner $! "Allowing GELF TLS input from LAN ($lan_subnet)..."
  log "GELF TLS input access allowed from LAN."

  # Enable UFW
  sudo ufw --force enable >/dev/null 2>&1 &
  spinner_with_runner $! "Enabling firewall..."
  log "Firewall enabled."

  # Display firewall status
  sudo ufw status >/dev/null 2>&1 &
  spinner_with_runner $! "Verifying firewall configuration..."
  log "Firewall configuration completed."
}

uninstall_everything() {
  section "Uninstalling MongoDB and Graylog"
  type_echo "[HACKER] Initiating complete removal of MongoDB and Graylog components..."

  # Stop and disable services
  type_echo "[HACKER] Stopping and disabling services..."
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

  # Reset firewall rules
  type_echo "[HACKER] Resetting firewall configuration..."
  sudo ufw --force reset >/dev/null 2>&1 &
  spinner_with_runner $! "Resetting UFW rules..."
  log "Firewall rules reset."

  # Purge packages
  type_echo "[HACKER] Removing installed packages..."
  purge_with_animation "Purging Graylog and MongoDB packages" graylog-server graylog-datanode mongodb-org mongodb-org-*
  log "Packages purged."

  # Remove configuration files, logs, data, and certificates
  type_echo "[HACKER] Cleaning up configuration files, data, and certificates..."
  sudo rm -rf /etc/graylog /var/log/graylog-server /var/log/graylog-datanode /var/lib/mongodb /var/log/mongodb /etc/sysctl.d/99-graylog-datanode.conf /tmp/graylog-repo.deb /etc/graylog/certs >/dev/null 2>&1 &
  spinner_with_runner $! "Removing configuration files, logs, data, and certificates..."
  log "Configurations, data, and certificates removed."

  # Remove repositories
  type_echo "[HACKER] Removing MongoDB and Graylog repositories..."
  sudo rm -f /etc/apt/sources.list.d/mongodb-org-8.0.list /etc/apt/sources.list.d/graylog.list /usr/share/keyrings/mongodb-server-8.0.gpg >/dev/null 2>&1 &
  spinner_with_runner $! "Removing repository configurations..."
  sudo apt-get update -y >/dev/null 2>&1 &
  spinner_with_runner $! "Updating package lists..."
  log "Repositories removed."

  section "Uninstallation Complete"
  type_echo "[HACKER] MongoDB and Graylog have been completely removed."
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
    configure_tls
    configure_firewall

    section "Tailing Graylog Server Log"
    type_echo "[HACKER] Displaying recent log entries for verification..."
    tail /var/log/graylog-server/server.log

    section "Installation Complete"
    type_echo "[HACKER] Graylog is alive (if services are up)."
    echo -e "${CYAN}Web UI:${RESET} https://<server-ip>:9443"
    echo -e "${CYAN}Tail logs:${RESET} sudo tail -f /var/log/graylog-server/server.log"
    echo -e "${CYAN}Note:${RESET} Configure Syslog TLS (port 6514) and GELF TLS (port 12201) inputs in Graylog web UI."
    ip addr show
  fi
}
main "$@"
