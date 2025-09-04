#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

main() {
  echo "Starting Graylog Server installer"

  sudo apt-get install graylog-server
  echo -n "Enter Password: " && head -1 </dev/stdin | tr -d '\n' | sha256sum | cut -d" " -f1
  sudo sed -i "/password_secret/c$(sed -n '/password_secret/{p;q}' /etc/graylog/datanode/datanode.conf)" /etc/graylog/server/server.conf
  sudo sed -i '0,/http_bind_address/{s|.*http_bind_address.*|http_bind_address = 0.0.0.0:9000|}' /etc/graylog/server/server.conf
  

}

main "$@"
