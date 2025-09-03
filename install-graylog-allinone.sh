#!/bin/bash
set -e

# Update and install prerequisites
sudo apt-get update
sudo apt-get install -y gnupg curl wget apt-transport-https
sudo apt-get install -y openjdk-17-jre-headless  # Graylog 6.x requires Java 17+

# Install MongoDB 8.0 (Ubuntu 24.04 "noble"):contentReference[oaicite:35]{index=35}
curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | \
  sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor
echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg] \
https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" | \
  sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list
sudo apt-get update
sudo apt-get install -y mongodb-org
sudo apt-mark hold mongodb-org

# Configure MongoDB to bind to all interfaces:contentReference[oaicite:36]{index=36}
sudo sed -i 's/^\( *bindIp:.*\)/#\1/' /etc/mongod.conf
sudo sed -i '/^net:/,/^$/ { /^  port:/a\  bindIpAll: true }' /etc/mongod.conf

# Start MongoDB
sudo systemctl daemon-reload
sudo systemctl enable --now mongod.service

# Install Graylog repository and Data Node:contentReference[oaicite:37]{index=37}
wget https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb
sudo dpkg -i graylog-6.3-repository_latest.deb
sudo apt-get update
sudo apt-get install -y graylog-datanode

# Increase vm.max_map_count for OpenSearch:contentReference[oaicite:38]{index=38}
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-graylog-datanode.conf
sudo sysctl --system

# Generate password_secret (used by Data Node and Graylog):contentReference[oaicite:39]{index=39}
PASS_SECRET=$(openssl rand -hex 32)
echo "password_secret: $PASS_SECRET"

# Configure Data Node
sudo tee -a /etc/graylog/datanode/datanode.conf > /dev/null <<EOF
password_secret = $PASS_SECRET
opensearch_heap = 1g
mongodb_uri = mongodb://localhost:27017/graylog
EOF

# Start Data Node
sudo systemctl daemon-reload
sudo systemctl enable --now graylog-datanode.service

# Install Graylog Server:contentReference[oaicite:40]{index=40}
sudo apt-get install -y graylog-server

# Prompt for Graylog admin password and set it in config:contentReference[oaicite:41]{index=41}
read -s -p "Enter Graylog admin password: " GL_PASS
echo
ROOT_PASS_SHA2=$(echo -n "$GL_PASS" | sha256sum | cut -d' ' -f1)

# Configure Graylog server.conf
sudo sed -i "s/^#password_secret =.*$/password_secret = $PASS_SECRET/" /etc/graylog/server/server.conf
sudo sed -i "s/^#root_password_sha2 =.*$/root_password_sha2 = $ROOT_PASS_SHA2/" /etc/graylog/server/server.conf
sudo sed -i "s/^#http_bind_address =.*$/http_bind_address = 0.0.0.0:9000/" /etc/graylog/server/server.conf

# Set Graylog Java heap (here 2g on a small server):contentReference[oaicite:42]{index=42}
sudo sed -i 's/^GRAYLOG_SERVER_JAVA_OPTS.*/GRAYLOG_SERVER_JAVA_OPTS="-Xms2g -Xmx2g -server -XX:+UseG1GC -XX:-OmitStackTraceInFastThrow"/' /etc/default/graylog-server

# Start Graylog
sudo systemctl daemon-reload
sudo systemctl enable --now graylog-server.service

echo "Installation complete. Graylog should be running on port 9000."
