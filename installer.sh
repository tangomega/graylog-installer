#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# ============================
#   ULTRA-HACKER INSTALLER
#   (Commands untouched)
# ============================

# Colors & effects
CSI="\033["
RESET="${CSI}0m"
BOLD="${CSI}1m"
DIM="${CSI}2m"

NEON1="${CSI}38;5;82m"    # green-ish
NEON2="${CSI}38;5;45m"    # cyan
NEON3="${CSI}38;5;201m"   # magenta
NEON4="${CSI}38;5;208m"   # orange
ERROR="${CSI}38;5;196m"   # red
WARN="${CSI}38;5;220m"    # yellow
OK="${CSI}38;5;112m"      # light green

# --- ASCII Banner ---
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

# --- utility visuals ---
typewriter() {
  local text="$1"
  local delay=${2:-0.008}
  for ((i=0;i<${#text};i++)); do
    printf "%s" "${text:i:1}"
    sleep "$delay"
  done
  printf "\n"
}

pretty_box() {
  local title="$1"
  printf "\n${NEON2}╔════════════════════════════════════════════════════════╗${RESET}\n"
  printf "${NEON2}║${RESET} ${BOLD}${NEON3}% -35s${RESET} ${NEON2}║${RESET}\n" "$title"
  printf "${NEON2}╚════════════════════════════════════════════════════════╝${RESET}\n\n"
}

glow_progress() {
  local msg="$1"; local secs=${2:-2}
  printf "${NEON2}["
  local steps=30
  local sleep_t=$(awk "BEGIN {print $secs/$steps}")
  for ((i=1;i<=steps;i++)); do
    printf "${NEON1}#${RESET}"
    sleep "$sleep_t"
  done
  printf "${NEON2}]${RESET} ${OK}${msg}${RESET}\n"
}

sig_line() {
  echo -e "${NEON4}────────────────────────────────────────────────────────${RESET}"
}

# --- Start ---
ascii_banner
sleep 0.6
typewriter "${NEON2}Boot sequence complete. Loading installer routines..." 0.007
sig_line
typewriter "${NEON1}Tip: All commands are preserved verbatim. This script adds only visual flair." 0.006
sig_line

# ========== ORIGINAL INSTALL STEPS ==========
main() {
  pretty_box "${BOLD}Phase 1 — Essentials & MongoDB${RESET}"
  typewriter "${NEON3}→ Updating apt and installing base tools..." 0.006
  glow_progress "Preparing package database" 0.8

  # Install essential packages
  sudo apt-get update
  sudo apt-get install -y gnupg curl lsb-release

  # Install MongoDB
  sudo curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor
  echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list
  sudo apt-get update
  sudo apt-get install -y mongodb-org
  sudo apt-mark hold mongodb-org

  sudo sed -i '/bindIp/c\  bindIpAll: true' /etc/mongod.conf
  sudo systemctl daemon-reload
  sleep 2
  sudo systemctl enable mongod.service
  sleep 2
  sudo systemctl start mongod.service
  sleep 2

  pretty_box "${BOLD}Phase 2 — Graylog DataNode${RESET}"
  sudo apt install -y gnupg curl wget apt-transport-https openssl ca-certificates jq openjdk-17-jre-headless
  wget https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb
  sudo dpkg -i graylog-6.3-repository_latest.deb
  sudo apt-get update
  sudo apt-get install graylog-datanode

  echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.d/99-graylog-datanode.conf
  sudo sysctl --system
  sudo sed -i "/password_secret/c\\password_secret = $(openssl rand -hex 32)" /etc/graylog/datanode/datanode.conf
  sudo sed -i "/mongodb_uri/c\\mongodb_uri = mongodb://127.0.0.1:27017/graylog" /etc/graylog/datanode/datanode.conf
  echo "opensearch_heap = 4g" >> /etc/graylog/datanode/datanode.conf
  sudo systemctl daemon-reload
  sleep 2
  sudo systemctl enable graylog-datanode.service
  sleep 2
  sudo systemctl start graylog-datanode
  sleep 2

  pretty_box "${BOLD}Phase 3 — Graylog Server${RESET}"
  sudo apt-get install graylog-server
  sudo sed -i "/password_secret/c$(sed -n '/password_secret/{p;q}' /etc/graylog/datanode/datanode.conf)" /etc/graylog/server/server.conf
  sudo sed -i '0,/http_bind_address/{s|.*http_bind_address.*|http_bind_address = 0.0.0.0:9000|}' /etc/graylog/server/server.conf
  read -sp "Enter Password: " pw && echo && hash=$(echo -n "$pw" | sha256sum | cut -d' ' -f1) && sudo sed -i "/^root_password_sha2 =/c\root_password_sha2 = $hash" /etc/graylog/server/server.conf
  sudo sed -i '/^GRAYLOG_SERVER_JAVA_OPTS="-Xms1g/c\GRAYLOG_SERVER_JAVA_OPTS="-Xms2g -Xmx2g -server -XX:+UseG1GC -XX:-OmitStackTraceInFastThrow"' /etc/default/graylog-server
  sudo systemctl daemon-reload
  sleep 2
  sudo systemctl enable graylog-server.service
  sleep 2
  sudo systemctl start graylog-server.service
  sleep 5

  echo
  echo -e "${NEON1}${BOLD}► Launching Graylog logs (live preview)${RESET}"
  sig_line
  tail -n +1 /var/log/graylog-server/server.log | sed -n '1,120p'
  sig_line
  echo -e "${NEON2}${BOLD}Installation complete. ${NEON3}Access Graylog → http://<server-ip>:9000${RESET}\n"
}

main "$@"
