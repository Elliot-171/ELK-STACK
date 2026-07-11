# Web Authentication Telemetry & Threat Detection Pipeline

## 📌 Project Overview
This lab demonstrates how to deploy, configure, and monitor a security event pipeline using **Elasticsearch, Kibana, and Filebeat** to track web-based authentication activity. By hosting a custom database-driven login application on an **Ubuntu Server** instance, I established an explicit telemetry model that passes authentication states directly into standard web server logs. This allows for the engineering of high-fidelity threat monitoring tables and metric analytics inside the Elastic SIEM platform without the complexity of backend database tracking.

### Core Objectives:
* **Log Pipeline Configuration:** Configure Filebeat modules to systematically ingest and parse Apache web server logs natively into the Elastic Common Schema (ECS).
* **Telemetry Tele-Engineering:** Develop a custom PHP authentication script (`login.php`) designed to explicitly embed success/failure vectors and target usernames into loggable URL query parameters.
* **Analyst Dashboard Optimization:** Customize pre-built Kibana dashboards to extract and isolate user authentication data into structured, side-by-side attack analysis matrices.

---

## 🛠️ Infrastructure & Environment Setup
* **SIEM / Analyzer Host:** Elastic Stack (Elasticsearch & Kibana v8.x) running on Host OS (`192.168.56.1:5601`)
* **Target Endpoint / Guest VM:** Ubuntu Server running Apache2, PHP (with SQLite3 support), and an active Filebeat module pipeline (`192.168.56.101`)
* **Attacker Simulation Host:** Kali Linux / Host Command Line Terminal (`192.168.56.1`)
* **Network Context:** Isolated VirtualBox Host-Only Network Adapter (`192.168.56.X`), completely segmented from the public internet.

---

## 💻 Web Application Architecture & Telemetry Design

To handle live user creation and state checking, this system integrates a local, file-based **SQLite** database via PHP Data Objects (PDO). Passwords are cryptographically salted and hashed using `password_hash()` prior to database commitment. 

When a session authenticates against the database records, the application processes the transaction and executes an HTTP redirect wrapper that explicitly passes the metadata states (`login=success` or `login=failed`) into the Apache `access.log` stream.

### Application Logic (`login.php`):
```php
<?php
$message = "";
$db_file = '/var/www/html/secure_lab.db';

// Automatically initialize the SQLite database if it doesn't exist
try {
    $db = new PDO("sqlite:" . $db_file);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )");
} catch (PDOException $e) {
    die("Database Initialization Failed: " . $e->getMessage());
}

// Handle Action Requests (POST)
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action'])) {
    $username = trim($_POST['user']);
    $password = $_POST['pass'];

    if (empty($username) || empty($password)) {
        $message = "<p style='color:orange;'><strong>Error:</strong> All fields are required.</p>";
    } 
    
    // REGISTRATION BLOCK
    elseif ($_POST['action'] === 'register') {
        try {
            $password_hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $db->prepare("INSERT INTO users (username, password_hash) VALUES (:username, :password_hash)");
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':password_hash', $password_hash);
            $stmt->execute();
            $message = "<p style='color:green;'><strong>Registration successful!</strong> You can now log in.</p>";
        } catch (PDOException $e) {
            if ($e->getCode() == 23000) {
                $message = "<p style='color:red;'><strong>Registration Error:</strong> Username already taken.</p>";
            } else {
                $message = "<p style='color:red;'><strong>Error:</strong> " . $e->getMessage() . "</p>";
            }
        }
    } 
    
    // LOGIN BLOCK
    elseif ($_POST['action'] === 'login') {
        $stmt = $db->prepare("SELECT password_hash FROM users WHERE username = :username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $user_record = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user_record && password_verify($password, $user_record['password_hash'])) {
            header("Location: login.php?login=success&user=" . urlencode($username));
            exit();
        } else {
            header("Location: login.php?login=failed&user=" . urlencode($username));
            exit();
        }
    }
}

// Process Telemetry parameters for screen messaging
if (isset($_GET['login'])) {
    if ($_GET['login'] === 'success') {
        $slotsname = htmlspecialchars($_GET['user']);
        $message = "<p style='color:green;'><strong>Success:</strong> Welcome back, $slotsname! (Authenticated via DB)</p>";
    } elseif ($_GET['login'] === 'failed') {
        $message = "<p style='color:red;'><strong>Authentication Error:</strong> Invalid database credentials.</p>";
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>Dynamic Authentication Portal</title></head>
<body>
    <h1>Dynamic Database Authentication Portal</h1>
    <hr>
    <?php echo $message; ?>
    <table border="0" cellpadding="10">
        <tr>
            <td valign="top" style="border-right: 1px solid #ccc; width: 45%;">
                <h2>User Login</h2>
                <form method="POST" action="login.php">
                    <input type="hidden" name="action" value="login">
                    <label>Username:</label><br>
                    <input type="text" name="user" required><br><br>
                    <label>Password:</label><br>
                    <input type="password" name="pass" required><br><br>
                    <input type="submit" value="Log In">
                </form>
            </td>
            <td valign="top" style="width: 45%; padding-left: 20px;">
                <h2>Register New Account</h2>
                <form method="POST" action="login.php">
                    <input type="hidden" name="action" value="register">
                    <label>Choose Username:</label><br>
                    <input type="text" name="user" required><br><br>
                    <label>Choose Password:</label><br>
                    <input type="password" name="pass" required><br><br>
                    <input type="submit" value="Create Account">
                </form>
            </td>
        </tr>
    </table>
</body>
</html>
```

---

## 🔧 SIEM Data Pipeline & Host Configuration

To support data management and prevent log ingestion failure paths, environmental configurations were applied to both the runtime engine and file system.

### 1. Endpoint Driver & Permission Adjustments
To support the dynamic interaction layer and ensure Apache has file system access to maintain the database, run these steps on the target endpoint:
```bash
# Install the missing PHP database connectors
sudo apt update && sudo apt install php-sqlite3 -y
sudo systemctl restart apache2

# Apply correct read/write permissions for the low-privilege www-data execution space
sudo chown -R www-data:www-data /var/www/html/
sudo chmod 755 /var/www/html/
```

### 2. Filebeat Module Activation
```bash
sudo filebeat modules enable apache
```

### 3. Streamlining `filebeat.yml`
```yaml
filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

setup.kibana:
  host: "http://192.168.56.1:5601"

filebeat.inputs:
- type: log
  enabled: false  # Disabled to force standard parsing explicitly through the apache module
  paths:
    - /var/log/auth.log
    - /var/log/syslog
    - /var/log/apache2/access.log
    - /var/log/apache2/error.log
```

---

## 🚀 Threat Simulation & Telemetry Verification

### 1. Simulating an Authentication Brute-Force Campaign
```bash
for i in {1..5}; do 
  curl -s "http://192.168.56.101/login.php?login=failed&user=database_target$i" > /dev/null
done
```
* **Telemetry Output:** Populates 5 distinct events verifying brute-force actions targeting dynamically structured identity profiles.

### 2. Simulating a Successful Authorization Event
```bash
curl -s "http://192.168.56.101/login.php?login=success&user=newly_registered_user" > /dev/null
```

---

## 📊 Kibana Analyst Dashboard Engineering

I modified the pre-built **`[Filebeat Apache] Access and Error Logs`** visualization dashboard to incorporate customized analytical data grids using Kibana Lens. By drawing on the engineered metadata parameters, the SIEM now populates live side-by-side matrices:

### 1. Authentication Failures Panel
* **Visualization Format:** Table
* **KQL Filtering Scope:** `url.query : *login=failed* and event.dataset : "apache.access"`
* **Row Configuration:** `url.query` (or `url.query.keyword`)
* **Metric Column:** `Count of records`

### 2. Authentication Successes Panel
* **Visualization Format:** Table
* **KQL Filtering Scope:** `url.query : *login=success* and event.dataset : "apache.access"`
* **Row Configuration:** `url.query` (or `url.query.keyword`)
* **Metric Column:** `Count of records`

---

## 📂 Repository File Layout
```text
├── README.md               # Full database-integrated SIEM engineering report
└── login.php               # SQLite multi-action code template
```
