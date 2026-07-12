# Designing a SIEM Detection Rule for Directory Brute-Forcing

This document outlines the engineering process for creating a custom security detection rule inside the Elastic Stack. This rule continuously monitors web pipeline logs to detect and alert on automated directory busting utilities (such as Gobuster, Dirbuster, or Feroxbuster) attempting to discover unlinked files or hidden paths on the server.

---

## 🔍 1. Understanding the Attack Signature

Directory brute-forcing relies on speed. Attack tools blast thousands of HTTP GET requests per minute using massive wordlists.

Because the vast majority of these paths do not exist, the attack leaves behind a distinct footprint: a massive, sudden spike in **HTTP 404 Not Found** response codes originating from a single source IP.

### Raw Log Footprint (`/var/log/apache2/access.log`)

```
192.168.56.1 - - [12/Jul/2026:11:02:15 +0000] "GET /admin/ HTTP/1.1" 404 462 "-" "gobuster/3.6.0"
192.168.56.1 - - [12/Jul/2026:11:02:15 +0000] "GET /backup/ HTTP/1.1" 404 462 "-" "gobuster/3.6.0"
192.168.56.1 - - [12/Jul/2026:11:02:15 +0000] "GET /config.php.bak HTTP/1.1" 404 462 "-" "gobuster/3.6.0"
```

### Key SIEM Detection Indicators (ECS Fields)

- **`http.response.status_code`** — Set to `404`.
- **`user_agent.original`** — Often reveals the tool name (e.g., `gobuster`), though sophisticated attackers will randomize this value.
- **`source.ip`** — The fixed attacker machine endpoint routing the requests.

---

## 🛡️ 2. SIEM Detection Rule Blueprint

To build this rule inside the Elastic SIEM interface, navigate to **Security > Rules > Create rule**. We will utilize a **Threshold Rule** architecture, which triggers an alert only when a specific query occurs a predetermined number of times within a set time window.

### Rule Metadata & Logic Settings

| Setting | Configuration / Value | Operational Justification |
|---|---|---|
| **Rule Type** | Threshold Rule | Best for recognizing high-velocity volumetric scanning behavior. |
| **Index Pattern** | `filebeat-*` | Points directly to our incoming Apache telemetry pipeline indices. |
| **Custom Query (KQL)** | `http.response.status_code : 404` | Filters out all successful noise, focusing purely on file-not-found errors. |
| **Threshold** | `> 50` | Triggers if an endpoint generates more than 50 path errors. |
| **Group By (Cardinality)** | `source.ip` | Tracks the threshold per individual attacker, preventing false alerts from distributed users. |
| **Time Window** | 1 minute | Tracks the velocity of requests (50 errors in 60 seconds indicates automation). |

---

## ⚙️ 3. Step-by-Step Kibana Implementation

Follow these steps to deploy and lock the rule into your SIEM console:

1. **Initialize the Rule Definition** — *Security Hub*
   Navigate to **Security > Rules**, click **Create rule**, and select **Threshold** as your logical execution framework.

2. **Apply the Telemetry Query Criteria** — *Index & Query Definitions*
   Set the index pattern target explicitly to `filebeat-*`. Inside the KQL search query box, define your baseline constraint string:
   ```
   http.response.status_code : 404
   ```

3. **Establish Alert Threshold Limits** — *Volumetric Constraints*
   Scroll down to the Threshold parameters. Set the trigger logic to evaluate if the event count is greater than **50**. Set the **Group By** field vector token precisely to `source.ip` and define the running window interval as **1 minute**.

4. **Configure Alert Details & Severity** — *Triage Metadata*
   Assign an analytical description layout to the alert properties:
   - **Rule Name:** High-Velocity Web Directory Brute-Forcing Detected
   - **Description:** Detects anomalous spikes in HTTP 404 responses from a single source, indicating directory busting utilities (Gobuster, Dirbuster) are actively mapping the file system.
   - **Severity:** Medium (can be elevated to High if the same IP suddenly generates a subsequent 200 or 302 code on a sensitive path).

5. **Set the Rule Execution Schedule** — *Scheduling Frequency*
   Set the rule to run every **5 minutes** with a lookback window of **1 minute** buffer space. This ensures continuous, low-overhead evaluation of your log indexes.

---

## 🧪 4. Testing & Rule Validation

To verify that your detection rule activates correctly under load, run a directory scan from your host machine or Kali Linux instance targeting your application VM:

```bash
# Simulating an attack using Gobuster
gobuster dir -u http://192.168.56.100/ -w /usr/share/wordlists/dirb/common.txt -t 20
```

### Expected Analyst Triage Workflow

1. Within 5 minutes, the Elastic SIEM engine evaluates the incoming index logs and recognizes that `192.168.56.1` generated hundreds of 404 errors within a single minute.
2. The rule trips, generating an alert record in the **Security Alerts Dashboard**.
3. An analyst investigating the alert can pivot into **Timeline View**, group by `source.ip`, and instantly see the exact web directory paths the attacker was attempting to uncover.
