# Detailed Installation & Deployment Guide

This document provides a step-by-step walkthrough for standing up the entire lab infrastructure. It includes installing the Elastic Stack on your Analyst Host machine, configuring the Apache/PHP/SQLite environment on the Ubuntu Server VM, and deploying Filebeat to tie the telemetry together.

---

## 🛠️ Prerequisites & Network Scheme

Before starting, ensure you have **VirtualBox** installed and a host operating system (e.g., Kali Linux, Windows, or macOS) with at least **8GB RAM** allocated for running the SIEM engine.

### Network Configuration (Host-Only Network)

To prevent telemetry loops and isolate lab traffic, configure a dedicated VirtualBox network:

1. Go to **VirtualBox Tools > Network Manager**.
2. Create a new **Host-Only Adapter** (e.g., `vboxnet0`).
3. Set the Host IP manually to: `192.168.56.1`.
4. Turn off the **DHCP Server** sub-tab to maintain strict control over server IPs.
5. In your Ubuntu Server VM network settings, change **Attached to** to **Host-Only Adapter** and select `vboxnet0`.

---

## 🏗️ Step 1: Analyst Host Setup (Elasticsearch & Kibana)

Execute these commands on your Host Machine / Analyst Node to download, configure, and initialize the Elastic Stack components.

### 1. Install Elastic Repository Keys
*Host OS Terminal*

Import the official Elastic GPG key and add the repository definitions to your local package index.

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update
```

### 2. Deploy Elasticsearch
*Inbound Port 9200*

Install the package and modify its configuration to listen explicitly across your virtual network interface.

```bash
sudo apt install elasticsearch
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Ensure the following configuration variables match:

```yaml
network.host: "192.168.56.1"
http.port: 9200
xpack.security.enabled: true
```

Start the background service process daemon:

```bash
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
```

### 3. Reset Superuser Password
*Write down the credential output*

Initialize or reset the built-in `elastic` user account password. This token is required for Kibana and Filebeat authentication chains.

```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i
```

### 4. Deploy and Link Kibana
*Inbound Port 5601*

Install Kibana on your host machine to visualize data matrices.

```bash
sudo apt install kibana
sudo nano /etc/kibana/kibana.yml
```

Apply the configuration mappings to link it straight to the Elasticsearch backend engine:

```yaml
server.host: "localhost"
server.port: 5601
elasticsearch.hosts: ["http://192.168.56.1:9200"]
elasticsearch.username: "elastic"
elasticsearch.password: "YOUR_RESET_PASSWORD_HERE"
```

Launch the visualization framework dashboard engine:

```bash
sudo systemctl enable kibana
sudo systemctl start kibana
```

---

## 🐧 Step 2: Target Endpoint Setup (Apache, PHP, SQLite)

Boot up your Ubuntu Server VM terminal window. We will assign a persistent static IP matching our host switch scheme and deploy the login platform application files.

### 1. Assign Static Network Address

Open your netplan layout mapping document file:

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

Rewrite the network interface configuration layout to assign a persistent internal lab identity:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3: # Substitute with your real interface identifier string
      dhcp4: no
      addresses:
        - 192.168.56.100/24
```

Apply the configuration shift changes safely:

```bash
sudo netplan apply
```

### 2. Install Web Environment Dependencies

Run a full package repository update checklist and install the web deployment layer packages:

```bash
sudo apt update
sudo apt install apache2 php php-sqlite3 libapache2-mod-php -y
```

### 3. Deploy Application Portal Script

Wipe the generic web page and inject your production `login.php` tracking application script:

```bash
sudo rm /var/www/html/index.html
sudo nano /var/www/html/login.php
```

*(Paste the complete database-driven `login.php` script code structure directly inside the file here.)*

### 4. Apply Directory Permissions

Secure your application directories while ensuring that the internal Apache service account daemon (`www-data`) can safely write state tracking records to the local SQLite database space file:

```bash
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html
```

---

## 🦫 Step 3: Pipeline Integration (Filebeat Ingestion)

With your application actively writing authentication traces into the local Apache logs, deploy the Filebeat agent on the Ubuntu Server VM to dynamically structure and forward this telemetry to the SIEM cluster.

### 1. Install Filebeat Agent Engine

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update && sudo apt install filebeat -y
```

### 2. Configure Output Targets (`filebeat.yml`)

Modify the primary daemon blueprint document:

```bash
sudo nano /etc/filebeat/filebeat.yml
```

Strip the default templates out and ensure your production tracking settings reflect your master configuration values precisely:

```yaml
# ============================== Filebeat Inputs ===============================
filebeat.inputs:
  - type: filestream
    id: apache-access-stream
    enabled: true
    paths:
      - /var/log/apache2/access.log

# ============================== Filebeat Modules ==============================
filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

# ================================== Outputs ===================================
output.elasticsearch:
  hosts: ["http://192.168.56.1:9200"]
  username: "elastic"
  password: "YOUR_RESET_PASSWORD_HERE" # <-- Provide your real elastic token string
```

### 3. Activate the Apache Parsing Module

Instruct Filebeat to load its native Apache processor matrix to automatically convert raw strings into Elastic Common Schema (ECS) data fields before transmission:

```bash
sudo filebeat modules enable apache
```

### 4. Start the Harvesting Daemon

Reload the service manager, register Filebeat on system startup, and launch the real-time telemetry forwarder:

```bash
sudo systemctl daemon-reload
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

### 5. Confirm Operational Pipeline

Verify that your logging pipeline is actively parsing and forwarding metrics without throwing authentication or connectivity errors:

```bash
sudo systemctl status filebeat
```

---

## 🔍 Step 4: Verification Checklist

- [ ] Open your browser on the host machine and access `http://localhost:5601` to load your Kibana SIEM interface.
- [ ] Navigate to **Management > Stack Management > Data Views** and construct a new tracking filter template targeting `filebeat-*`.
- [ ] Open the **Discover** tab and verify that inbound fields like `url.query` cleanly capture live authentication attempts generated by interactions with `http://192.168.56.100/login.php`.

---

## Notes

- Replace `YOUR_RESET_PASSWORD_HERE` in both `kibana.yml` and `filebeat.yml` with the actual password generated during the `elasticsearch-reset-password` step.
- Replace `enp0s3` in the netplan config with the actual interface name reported by `ip a` on your Ubuntu Server VM.
- This environment is intended to run entirely on an isolated Host-Only virtual network and should not be bridged to a production or public-facing network.
