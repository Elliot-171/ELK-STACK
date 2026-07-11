<?php
$message = "";
$db_file = '/var/www/html/secure_lab.db';

// 1. Automatically initialize the SQLite database if it doesn't exist
try {
    $db = new PDO("sqlite:" . $db_file);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Create the users table if it isn't there yet
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )");
} catch (PDOException $e) {
    die("Database Initialization Failed: " . $e->getMessage());
}

// 2. Handle Action Requests (POST)
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action'])) {
    $username = trim($_POST['user']);
    $password = $_POST['pass'];

    if (empty($username) || empty($password)) {
        $message = "<p style='color:orange;'><strong>Error:</strong> All fields are required.</p>";
    } 
    
    // --- REGISTRATION BLOCK ---
    elseif ($_POST['action'] === 'register') {
        try {
            // Hash the password securely before saving (Standard industry security practices)
            $password_hash = password_hash($password, PASSWORD_DEFAULT);
            
            $stmt = $db->prepare("INSERT INTO users (username, password_hash) VALUES (:username, :password_hash)");
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':password_hash', $password_hash);
            $stmt->execute();
            
            $message = "<p style='color:green;'><strong>Registration successful!</strong> You can now log in.</p>";
        } catch (PDOException $e) {
            // Checks if username already exists
            if ($e->getCode() == 23000) {
                $message = "<p style='color:red;'><strong>Registration Error:</strong> Username already taken.</p>";
            } else {
                $message = "<p style='color:red;'><strong>Error:</strong> " . $e->getMessage() . "</p>";
            }
        }
    } 
    
    // --- LOGIN BLOCK ---
    elseif ($_POST['action'] === 'login') {
        $stmt = $db->prepare("SELECT password_hash FROM users WHERE username = :username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $user_record = $stmt->fetch(PDO::FETCH_ASSOC);

        // Verify user exists and password matches hashed password
        if ($user_record && password_verify($password, $user_record['password_hash'])) {
            // SUCCESS: Redirect with telemetry tags
            header("Location: login.php?login=success&user=" . urlencode($username));
            exit();
        } else {
            // FAILURE: Redirect with telemetry tags
            header("Location: login.php?login=failed&user=" . urlencode($username));
            exit();
        }
    }
}

// 3. Process Telemetry parameters for screen messaging
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
<head>
    <title>Dynamic Authentication Portal</title>
</head>
<body>
    <h1>Dynamic Database Authentication Portal</h1>
    <hr>
    
    <?php echo $message; ?>

    <table border="0" cellpadding="10">
        <tr>
            <!-- Left Side: Login Interface -->
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

            <!-- Right Side: Registration Interface -->
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
