# Real-Time Log Analysis & Threat Decoding

This document serves as a standard analytical playbook for the environment. It walks through the process of auditing raw, unstructured web server access strings and analyzing how those logs are converted into normalized security alerts inside the SIEM architecture during an authentication attack.

---

## 🔬 1. Decoding the Raw Attack Signature

When a threat actor launches an automated dictionary or brute-force tool against the portal, the application forces a descriptive parameter injection into the URL string. This is captured instantly by the underlying Apache engine.

### Example Raw Log Entry (`/var/log/apache2/access.log`)

```
192.168.56.1 - - [12/Jul/2026:10:45:22 +0000] "POST /login.php HTTP/1.1" 302 462 "http://192.168.56.100/login.php" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
192.168.56.1 - - [12/Jul/2026:10:45:22 +0000] "GET /login.php?login=failed&user=admin HTTP/1.1" 200 1245 "http://192.168.56.100/login.php" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
```

### Anatomy of the Attack Log

An analyst reviewing this transactional pair can break down the exact progression of the attack vector:

1. **`192.168.56.1` (Source IP):** Identifies the origin of the request — in this case, the adversary operating from the host machine interface.
2. **`POST /login.php` (Phase 1 – The Attempt):** The actor submits an authentication request payload. The server evaluates it against `secure_lab.db` and issues an HTTP `302` redirect because the credentials failed verification.
3. **`GET /login.php?login=failed&user=admin` (Phase 2 – Telemetry Generation):** The client browser follows the redirect destination. The injected string metadata parameters explicitly flag a failed state targeting the default `admin` username.
4. **`HTTP 200` (Response Code):** The application renders the login failure screen back to the client interface.

---

## 🤖 2. The Normalization Blueprint (Elastic Common Schema)

Raw log text blocks are difficult to query at scale. When Filebeat harvests these entries using its internal `apache` module, it maps the unstructured string elements into standardized, indexable Elastic Common Schema (ECS) fields.

| Raw Apache Log Element | Mapped ECS Field Vector | Sample Normalized Value | Analytical Utility |
|---|---|---|---|
| `192.168.56.1` | `source.ip` | `192.168.56.1` | Used to block malicious infrastructure at the firewall level. |
| `admin` | `user.name` / `url.query` | `login=failed&user=admin` | Tracks which corporate accounts are being targeted for compromise. |
| `200` | `http.response.status_code` | `200` | Filters out server-side processing errors from actual access logs. |
| `Mozilla/5.0...` | `user_agent.original` | `Mozilla/5.0 (X11; ...)` | Identifies specific attack tools or script frameworks (e.g., Python-requests, Hydra). |

---

## 🎯 3. Threat Hunting Playbook via Kibana (KQL)

Once normalization completes, security analysts can hunt across the entire indexing cluster using structured Kibana Query Language (KQL) scripts instead of running slow `grep` searches across distributed endpoints.

### Query 1: Isolate All Authentication Failures

To immediately display all failed login attempts across the entire enterprise architecture:

```
url.query : *login=failed*
```

### Query 2: Detect Targeted Account Harvesting

To audit whether an adversary is cycling through common usernames (like `root`, `admin`, `guest`) from a single suspicious source address:

```
url.query : *login=failed* and source.ip : "192.168.56.1"
```

### Query 3: Spot Successful Logins Post-Attack

If a specific source IP generates 100 failures and then suddenly registers a success, it indicates a successful compromise. This high-severity event can be surfaced using:

```
url.query : *login=success* and source.ip : "192.168.56.1"
```

---

## 🚨 4. Alerting Threshold Recommendations

For a production deployment environment, the telemetry parsed through this pipeline can feed custom SIEM alert rules. The following thresholds are recommended for escalating these events to an active incident response queue:

### 📈 Brute-Force Authentication Attempt Detected

| Attribute | Value |
|---|---|
| **Condition** | `url.query : *login=failed*` |
| **Threshold** | Grouped by `source.ip` where the event count is greater than 20 occurrences within a 1-minute window. |
| **Severity** | High (Tier 2) — Indicates an active, automated dictionary tool is hitting the web service endpoint. |

### 🔴 Account Takeover (ATO) Confirmation

| Attribute | Value |
|---|---|
| **Condition** | A single `source.ip` registers a `url.query : *login=success*` within 5 minutes after generating greater than 10 `login=failed` events. |
| **Severity** | Critical (Tier 1) — Indicates a password guess was successful. This triggers an immediate, automated containment playbook to isolate the compromised user account session. |
