#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

main() {
  echo "Starting Graylog Server installer"

  sudo apt-get install graylog-server
  echo -n "Enter Password: " && head -1 </dev/stdin | tr -d '\n' | sha256sum | cut -d" " -f1
  sed -i "/password_secret/c$(sed -n '/password_secret/{p;q}' /etc/graylog/datanode/datanode.conf)" /etc/graylog/server/server.conf
  sed -n "http_bind_address

sed -n '/PATTERN/{p;q}' source.txt >> destination.txt
  
}

main "$@"
