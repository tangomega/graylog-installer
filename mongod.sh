#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

main() {
  #!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

main() {
  echo "Starting MongoDB installer"

  sudo service mongod stop || true
  sudo apt-get purge -y mongodb-org*
  sudo rm -rf /var/log/mongodb /var/lib/mongodb
  
  # Install essential packages
  sudo apt-get update
  sudo apt-get install -y gnupg curl lsb-release

  # Install MongoDB
  curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor
  echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/8.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list
  sudo apt-get update
  sudo apt-get install -y mongodb-org
  sudo apt-mark hold mongodb-org

  # Configure MongoDB
  sudo sed -i '/bindIp/c\  bindIpAll: true' /etc/mongod.conf
  echo "MongoDB configuration:"
  sudo cat /etc/mongod.conf

  sudo systemctl daemon-reload
  sudo systemctl enable mongod.service
  sudo systemctl start mongod.service

  echo "Running MongoDB health checks..."

  # Test 1: systemctl status
  if systemctl is-active --quiet mongod; then
    echo "[OK] mongod service is active"
  else
    echo "[FAIL] mongod service is NOT active"
    exit 1
  fi

  # Test 2: Check process
  if pgrep mongod > /dev/null; then
    echo "[OK] mongod process is running"
  else
    echo "[FAIL] mongod process not found"
    exit 1
  fi

  # Test 3: Test port listening
  if ss -ltn | grep -q ':27017'; then
    echo "[OK] MongoDB is listening on port 27017"
  else
    echo "[FAIL] MongoDB is NOT listening on port 27017"
    exit 1
  fi

  # Test 4: Connect with mongo shell
  if mongo --eval "db.adminCommand('ping')" &>/dev/null; then
    echo "[OK] MongoDB responded to ping"
  else
    echo "[FAIL] MongoDB did NOT respond to ping"
    exit 1
  fi

  echo "All MongoDB checks passed!"
}

main "$@"

}

main "$@"
