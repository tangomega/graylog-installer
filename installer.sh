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
  sudo sed -i '/bindIp/c\  bindIpAll: true' /etc/mongod.conf
  sudo cat /etc/mongod.conf
 
  sudo systemctl daemon-reload
  sudo systemctl enable mongod.service
  sudo systemctl start mongod.service
  sudo systemctl status mongod


  # Datanode
  echo "Starting Graylog DataNode installer"

  sudo systemctl stop graylog-datanode && sudo apt purge --autoremove -y graylog-datanode && sudo rm -rf /etc/graylog/datanode /var/lib/graylog-datanode /var/log/graylog-datanode && sudo apt update
  sudo apt install -y gnupg curl wget apt-transport-https openssl ca-certificates jq openjdk-17-jre-headless
  wget https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb
  sudo dpkg -i graylog-6.3-repository_latest.deb
  sudo apt-get update
  sudo apt-get install graylog-datanode
  echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.d/99-graylog-datanode.conf
  sudo sysctl --system
  cat /proc/sys/vm/max_map_count

  sudo sed -i "/password_secret/c\\password_secret = $(openssl rand -hex 32)" /etc/graylog/datanode/datanode.conf
  sudo sed -i "/mongodb_uri/c\\mongodb_uri = mongodb://127.0.0.1:27017/graylog" /etc/graylog/datanode/datanode.conf
  echo "opensearch_heap = 4g" >> /etc/graylog/datanode/datanode.conf
  sudo systemctl daemon-reload
  sudo systemctl enable graylog-datanode.service
  sudo systemctl start graylog-datanode

  #Graylog Server
  echo "Starting Graylog Server installer"

  sudo apt-get install graylog-server
  sudo sed -i "/password_secret/c$(sed -n '/password_secret/{p;q}' /etc/graylog/datanode/datanode.conf)" /etc/graylog/server/server.conf
  sudo sed -i '0,/http_bind_address/{s|.*http_bind_address.*|http_bind_address = 0.0.0.0:9000|}' /etc/graylog/server/server.conf
  sudo read -sp "Enter Password: " pw && echo && hash=$(echo -n "$pw" | sha256sum | cut -d' ' -f1) && sudo sed -i "/^root_password_sha2 =/c\root_password_sha2 = $hash" /etc/graylog/server/server.conf
  sudo sed -i '/^GRAYLOG_SERVER_JAVA_OPTS="-Xms1g/c\GRAYLOG_SERVER_JAVA_OPTS="-Xms2g -Xmx2g -server -XX:+UseG1GC -XX:-OmitStackTraceInFastThrow"' /etc/default/graylog-server
  sudo systemctl daemon-reload
  sudo systemctl enable graylog-server.service
  sudo systemctl start graylog-server.service
  tail /var/log/graylog-server/server.log
}

main "$@"
