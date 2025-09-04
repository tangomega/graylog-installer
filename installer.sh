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


  # Datanode
  echo "Starting Graylog DataNode installer"

  #Remove old files
  sudo systemctl stop graylog-datanode && sudo apt purge --autoremove -y graylog-datanode && sudo rm -rf /etc/graylog/datanode /var/lib/graylog-datanode /var/log/graylog-datanode && sudo apt update

  # Install essential packages
  sudo apt install -y gnupg curl wget apt-transport-https openssl ca-certificates jq openjdk-17-jre-headless

  # Install Graylog-Datanode repo
  wget https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb
  sudo dpkg -i graylog-6.3-repository_latest.deb
  sudo apt-get update
  sudo apt-get install graylog-datanode

  #Configure Datanode
  echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.d/99-graylog-datanode.conf
  sudo sysctl --system
  cat /proc/sys/vm/max_map_count

  sudo sed -i "/password_secret/c\\password_secret = $(openssl rand -hex 32)" /etc/graylog/datanode/datanode.conf
  sudo sed -i "/mongodb_uri/c\\mongodb_uri = mongodb://127.0.0.1:27017/graylog" /etc/graylog/datanode/datanode.conf
  echo "opensearch_heap = 4g" >> /etc/graylog/datanode/datanode.conf
  sudo systemctl daemon-reload
  sudo systemctl enable graylog-datanode.service
  sudo systemctl start graylog-datanode
  sudo systemctl status graylog-datanode
}

main "$@"
