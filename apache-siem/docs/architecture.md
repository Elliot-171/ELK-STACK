# Data Flow Architecture & System Topology
 
This document details the architectural framework, system components, and end-to-end data pipeline for the dynamic web authentication monitoring lab. The entire environment is fully virtualized and self-contained within an isolated network topology to ensure safe containment of simulated threat traffic.
 
---
 
## 🏗️ System Topology Overview
 
The lab environment bifurcates into two primary logical security zones over an isolated virtual network: the **Target Endpoint Node** (hosting the dynamic authentication app and local database) and the **Centralized SIEM Cluster** (handling data ingestion, indexation, and security analytics).
 
```
[ Attacker / User Simulation Host ]
                  │
                  │ (HTTP POST Requests / Brute-Force Replays)
                  ▼
┌────────────────────────────────────────────────────────  ┐
│ TARGET ENDPOINT NODE (Ubuntu Server VM)                  │
│                                                          │
│  ┌───────────┐    Commits Record   ┌────────────────┐    │
│  │ login.php │ ──────────────────> │ secure_lab.db  │    │
│  └─────┬─────┘                     │    (SQLite)    │    │
│        │                           └────────────────┘    │
│        │ Redirects & Logs Event                          │
│        ▼                                                 │
│  ┌──────────────────────┐                                │
│  │  apache2/access.log  │ <──────┐ Monitors Stream       │
│  └──────────────────────┘        │                       │
│                            ┌─────┴─────┐                 │
│                            │ Filebeat  │                 │
│                            └─────┬─────┘                 │
└──────────────────────────────────┼───────────────────────┘
                                   │ Ships Normalized Logs via Port 9200
                                   ▼
┌────────────────────────────────────────────────────────┐
│ CENTRALIZED SIEM CLUSTER (Host OS / Analyst Node)       │
│                                                          │
│  ┌───────────────┐                 ┌────────────┐        │
│  │ Elasticsearch │ ──────────────> │ Kibana SIEM│        │
│  │ (Data Index)  │  Query Engine   │ Dashboard  │        │
│  └───────────────┘                 └────────────┘        │
└──────────────────────────────────────────────────────────┘
```
 
---
 
## 🔄 End-to-End Data Lifecycle
 
The lifecycle of a single authentication event scales through four distinct phases across the infrastructure:
 
```
┌───────────────┐      ┌───────────────┐      ┌────────────────┐      ┌────────────────┐
│ 1. Generation │ ───> │  2. Ingestion │ ───> │ 3. Indexation  │ ───> │ 4. Visualiztn. │
└───────────────┘      └───────────────┘      └────────────────┘      └────────────────┘
```
 
### 1. Telemetry Generation Layer
- **User Interaction:** A user or script interacts with the login or registration tables inside `login.php`.
- **Database Ledger:** Registration actions pass inputs through PHP's `password_hash()` algorithm before storing them safely in the file-based SQLite database (`secure_lab.db`). Verification checks tap into the ledger using `password_verify()`.
- **Telemetry Injection:** Upon processing, the script uses an HTTP redirect wrapper to force key-value parameters (`login=success` or `login=failed`) alongside the targeted account user straight into the URL string.
- **Logging:** The Apache web server captures this inbound standard GET redirect natively, dropping the telemetry parameters cleanly into `/var/log/apache2/access.log`.
### 2. Log Ingestion & Harvesting Layer
- **Agent Status:** Filebeat runs as a persistent service on the Ubuntu server, tracking the active tail of the Apache log files.
- **Log Normalization:** Using its internal Apache module parsing architecture, Filebeat strips away raw string metadata, indexing components directly into the Elastic Common Schema (ECS) data model.
- **Transmission:** Normalized JSON events are shipped across the Host-Only network adapter straight to the analytics container via port `9200`.
### 3. Data Processing & Indexation Layer
- **Ingestion:** Elasticsearch captures the inbound payload streaming from the Filebeat daemon.
- **Indexation:** Events are partitioned chronologically into security indices (`filebeat-8.*`), instantly exposing fields like `url.query`, `http.response.status_code`, and `source.ip` for analytical searching.
### 4. Analyst Visualization Layer
- **Hunting:** Security analysts utilize the Kibana Discover interface to drill down into anomalous logs, inspecting telemetry components without needing messy manual substring regex tools.
- **Dashboard Aggregation:** Custom Kibana Lens tables isolate targeted KQL search strings (`url.query : *login=failed*`) to separate raw authentication waves from legitimate operational access in side-by-side grids.
---
 
## 🔒 Security & Data Controls
 
| Infrastructure Component | Security Control Applied | Operational Purpose |
|---|---|---|
| Web Application | Cryptographic Salting & Hashing | Shields backend user database records from plaintext compromise. |
| Local Database | Linux Access Control Lists (`chmod 755` / `www-data`) | Hardens the database layout by confining read/write permissions purely to the Apache execution process. |
| Log Shipper | Isolated Harvesting Profiles | Keeps system memory overhead low by tracking targeted server logs rather than generic whole-disk paths. |
| Network Switching | VirtualBox Host-Only Adapter | Air-gaps the infrastructure to completely prevent testing actions from spilling into production networks. |
 
---
 
## Stack Summary
 
| Layer | Technology |
|---|---|
| Web Server | Apache2 |
| Application | PHP (`login.php`) |
| Database | SQLite (`secure_lab.db`) |
| Log Shipper | Filebeat |
| Data Store / Index | Elasticsearch |
| Visualization | Kibana |
| Virtualization | VirtualBox (Host-Only Network) |
 
