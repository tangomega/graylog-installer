#!/usr/bin/env bash
set -euo pipefail

echo "=== Graylog Full Reset Script ==="
read -p "⚠️ This will REMOVE Graylog, MongoDB, and OpenSearch. Continue? (y/N): " confirm

if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Aborted."
    exit 1
fi

echo "--- Stopping services ---"
sudo systemctl stop graylog-server || true
sudo systemctl stop mongod || true
sudo systemctl stop opensearch || true

echo "--- Removing packages ---"
sudo apt-get purge -y graylog-server mongodb-org opensearch || true
sudo apt-get autoremove -y
sudo apt-get autoclean -y

echo "--- Removing data directories ---"
sudo rm -rf /var/lib/mongodb
sudo rm -rf /var/lib/opensearch
sudo rm -rf /var/lib/graylog-server
sudo rm -rf /etc/mongod.conf /etc/opensearch /etc/graylog

echo "--- Reset complete ---"
echo "You can now re-run the installer script to start fresh."
