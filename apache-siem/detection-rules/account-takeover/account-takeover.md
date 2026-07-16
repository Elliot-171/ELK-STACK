# Account Takeover (ATO) Detection via Event Correlation (EQL)

This document contains the engineering logic, event constraints, and verification procedures for the Post-Brute-Force Account Takeover (ATO) detection rule implemented within the Elastic SIEM infrastructure.

---

## 🔍 Rule Objective & Threat Profile

| Attribute | Value |
|---|---|
| **Rule Name** | Post-Brute-Force Account Takeover (ATO) Detection |
| **Rule Type** | Event Correlation Language (EQL) Sequence |
| **Severity** | High |
| **MITRE ATT&CK Mapping** | `T1110.001` – Brute Force: Password Guessing<br>`T1078` – Valid Accounts |

### Strategic Threat Scenario

Standard threshold alerts look for volumetric failures, but they frequently miss the critical moment when an attack switches from an attempt to a successful breach.

This rule maps a sequence across an explicit time window: it monitors a single source IP address actively spraying authentication failures across multiple system accounts, and tracks the exact moment that same source address registers a successful authentication response anywhere on the application interface, regardless of the targeted username.

---

## 🛠️ Detection Logic & EQL Syntax

The rule utilizes Elastic's Event Correlation Language (EQL) to stitch together state changes across independent log lines by binding them to a shared source network address.

```
sequence by source.ip with maxspan=5m
  [network where url.query : "*login=failed*"] with runs=10
  [network where url.query : "*login=success*"]
```

### Analytical Breakdown

- **`sequence by source.ip`** — Instructs the Elasticsearch query processing engine to track state sequences independently per unique source IP address. If two different attackers are scanning simultaneously, their pools are evaluated independently.
- **`with maxspan=5m`** — Establishes a strict 5-minute sliding window constraint. If the success event occurs 6 minutes after the brute-force wave drops off, it will not link the sequence, preventing false positive alarms from normal day-to-day user mistakes.
- **`with runs=10`** — A high-efficiency counter that requires at least 10 discrete failure log lines to index before moving the sequence tracking state to "pending validation."
- **`[network where url.query : "*login=success*"]`** — The sequence capstone. The moment this specific string matches an inbound JSON token from the same IP, the alert triggers immediately.

---

## ⚙️ Deployment Mappings

Apply these configuration variables within the Kibana Rule Creation engine (**Security > Rules > Create Rule > Event Correlation**):

| Configuration Variable | Setting Value | Operational Justification |
|---|---|---|
| **Index Pattern** | `filebeat-*` | Connects directly to our live, normalized Apache log streams. |
| **Schedule Frequency** | Run every 5 minutes | Minimizes Mean Time to Detect (MTTD) for active breaches. |
| **Lookback Window** | 1 minute | Evaluates the absolute hot edge of incoming data indices. |
| **Risk Score** | 73 / 100 | Escalates the event visually onto the primary SOC operations screen. |

---

## 🧪 Simulation & Automated Validation Playbook

To validate the immediate execution of this rule without waiting for scheduled engine cycles, run the following command block from your testing node to inject simulated telemetry traffic:

```bash
#!/usr/bin/env bash
# Step 1: Fire a rapid wave of 10 failed login parameters targeting random system profiles
for dummy in u1 u2 u3 u4 u5 u6 u7 u8 u9 u10; do
  curl -s -G "http://192.168.56.100/login.php" \
    --data-urlencode "login=failed" \
    --data-urlencode "user=${dummy}" > /dev/null
done
echo "[*] Phase 1 Complete: 10 Volumetric failures injected into Apache access logs."

# Step 2: Simulate an immediate breakthrough entry on a completely separate profile account
curl -s -G "http://192.168.56.100/login.php" \
  --data-urlencode "login=success" \
  --data-urlencode "user=legit_admin" > /dev/null
echo "[+] Phase 2 Complete: Success authentication validation trace pushed."
```

### Expected Alert Output Analysis

Upon sequence completion, an operational event structure will parse directly into the Kibana Security Alerts console:

1. **Trigger State:** The rule logs an active alert instantly.
2. **Investigative Focus:** The analyst can drill down into the event data grid to isolate the single `source.ip`, trace the history of the 10 targeted user account attempts, and pinpoint the exact account username compromised during Phase 2.
