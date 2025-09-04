#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

main() {
  echo "Starting MongoDB installer"
  sudo service mongod stop
  sudo apt-get purge mongodb-org*
  sudo rm -r /var/log/mongodb /var/lib/mongodb
  
  # Install essential packages
  sudo apt-get install gnupg curl

  # Install MongoDB
  curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor
  echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list
  sudo apt-get update
  sudo apt-get install -y mongodb-org
  sudo apt-mark hold mongodb-org

  #Configure MongoDB
  sudo sed -i '/bindIp/c\  bindIpAll: true' /etc/mongod.conf
  sudo cat /etc/mongod.conf
 
  sudo systemctl daemon-reload
  sudo systemctl enable mongod.service
  sudo systemctl start mongod.service
  sudo systemctl status mongod
}

main "$@"
