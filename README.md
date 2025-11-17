# Graylog + MongoDB Automated Installer

This repository contains an **automated Bash script** to install and configure a **Graylog server** with a **MongoDB backend** on Ubuntu/Debian systems.

The setup is designed for **local network environments** and is compatible with network devices like FortiGate for syslog ingestion.

---
## **Prerequisites**

- Ubuntu 24.04 / Debian 11+  
- Minimum **4GB RAM** (more recommended for larger deployments)  
- **Root or sudo privileges**  
- Open **TCP/UDP ports 2514** for syslog input (FortiGate integration)  
- Open **port 9000** for the Graylog web UI  

---

## **Installation**

```bash
git clone https://github.com/tangomega/graylog-installer && cd graylog-installer && chmod +x * && sudo ./installer.sh
```

## **Post-Installation: Graylog Web UI Configuration Guide**

After the script completes, Graylog will be available at:

```bash
http://<your-server-ip>:9000
```
