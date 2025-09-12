#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

main() {
  echo "Starting Graylog DataNode installer"

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
