#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

main() {
  echo "Starting Graylog Server installer"

  sudo apt-get install graylog-server
  sudo sed -i "/password_secret/c$(sed -n '/password_secret/{p;q}' /etc/graylog/datanode/datanode.conf)" /etc/graylog/server/server.conf
  sudo sed -i '0,/http_bind_address/{s|.*http_bind_address.*|http_bind_address = 0.0.0.0:9000|}' /etc/graylog/server/server.conf
  sudo read -sp "Enter Password: " pw && echo && hash=$(echo -n "$pw" | sha256sum | cut -d' ' -f1) && sudo sed -i "/^root_password_sha2 =/c\root_password_sha2 = $hash" /etc/graylog/server/server.conf
  sudo sed -i '/^GRAYLOG_SERVER_JAVA_OPTS="-Xms1g/c\GRAYLOG_SERVER_JAVA_OPTS="-Xms2g -Xmx2g -server -XX:+UseG1GC -XX:-OmitStackTraceInFastThrow"' /etc/default/graylog-server
  sudo systemctl daemon-reload
  sudo systemctl enable graylog-server.service
  sudo systemctl start graylog-server.service
  sudo systemctl status graylog-server.service
  tail /var/log/graylog-server/server.log
}

main "$@"
