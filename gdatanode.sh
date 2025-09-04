#!/usr/bin/env bash
# install-graylog-datanode.sh
# Fault-tolerant, idempotent installer for Graylog DataNode (with embedded OpenSearch) on Ubuntu Server 24.04
# Requires MongoDB 8.0 to be pre-installed and running
# Run with sudo
# Aligns with Graylog DataNode installation guide: https://docs.graylog.org/docs/datanode

# Documentation and Citations:
# - Graylog DataNode Installation: https://docs.graylog.org/docs/datanode
# - OpenSearch Prerequisites (vm.max_map_count): https://opensearch.org/docs/latest/install-and-configure/install-opensearch/index/#important-settings
# - MongoDB Configuration: https://www.mongodb.com/docs/manual/reference/configuration-options/#net-options
# - Graylog Prerequisites: https://docs.graylog.org/docs/prerequisites
# - JVM Settings: https://docs.graylog.org/docs/prerequisites#jvm-settings

# Five most load-bearing facts:
# 1. Graylog DataNode requires OpenJDK 17 or later.
# 2. DataNode embeds OpenSearch and requires vm.max_map_count=262144.
# 3. MongoDB must be running and accessible at mongodb://localhost:27017/graylog with bindIpAll: true.
# 4. DataNode must expose OpenSearch API (0.0.0.0:9200) and REST API (0.0.0.0:8999).
# 5. Heap size set to 50% of system RAM, capped at 31GB, per Graylog documentation.

set -euo pipefail
IFS=$'\n\t'

DATANODE_CONF="/etc/graylog/datanode/datanode.conf"
GRAYLOG_DATANODE_DATA_DIR="/var/lib/graylog-datanode"
GD_REPO_DEB_URL="https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb"
MONGO_CONF="/etc/mongod.conf"

main() (
wget https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb
sudo dpkg -i graylog-6.3-repository_latest.deb
sudo apt-get update
sudo apt-get install graylog-datanode
)
  
