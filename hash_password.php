<?php
/**
 * FIM Password Hash Utility
 * 
 * Simple utility to generate secure password hashes for FIM configuration.
 * Run this script to generate a hash for your admin password.
 * 
 * Usage:
 *   php hash_password.php
 *   php hash_password.php mypassword
 */

// Function to generate secure password hash
function generatePasswordHash($password) {
    // Use PHP's password_hash with default algorithm (currently bcrypt)
    return password_hash($password, PASSWORD_DEFAULT);
}

// Function to verify a password against a hash (for testing)
function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

// Command line usage
if (php_sapi_name() === 'cli') {
    if (isset($argv[1])) {
        // Password provided as command line argument
        $password = $argv[1];
        $hash = generatePasswordHash($password);
        
        echo "Password Hash Generated:\n";
        echo "========================\n";
        echo "Password: " . $password . "\n";
        echo "Hash: " . $hash . "\n\n";
        echo "Copy this hash to your fim-config.php file:\n";
        echo "'admin_password' => '" . $hash . "',\n\n";
        echo "Note: Delete this terminal history for security.\n";
    } else {
        // Interactive mode
        echo "FIM Password Hash Generator\n";
        echo "===========================\n\n";
        echo "Enter your desired admin password: ";
        $password = trim(fgets(STDIN));
        
        if (empty($password)) {
            echo "Error: Password cannot be empty.\n";
            exit(1);
        }
        
        $hash = generatePasswordHash($password);
        
        echo "\nPassword Hash Generated:\n";
        echo "========================\n";
        echo "Hash: " . $hash . "\n\n";
        echo "Copy this hash to your fim-config.php file:\n";
        echo "'admin_password' => '" . $hash . "',\n\n";
        echo "Note: Clear your terminal history for security.\n";
    }
} else {
    // Web-based usage (simple form)
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
        $password = $_POST['password'];
        
        if (empty($password)) {
            $error = "Password cannot be empty.";
        } else {
            $hash = generatePasswordHash($password);
            $success = true;
        }
    }
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>FIM Password Hash Generator</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
            .container { background: #f9f9f9; padding: 30px; border-radius: 8px; }
            .form-group { margin-bottom: 20px; }
            label { display: block; margin-bottom: 5px; font-weight: bold; }
            input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
            .btn { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
            .btn:hover { background: #005a8a; }
            .success { background: #d4edda; color: #155724; padding: 15px; border-radius: 4px; margin: 20px 0; }
            .error { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 4px; margin: 20px 0; }
            .hash-output { background: #f8f9fa; padding: 15px; border-radius: 4px; word-break: break-all; font-family: monospace; }
            .warning { background: #fff3cd; color: #856404; padding: 15px; border-radius: 4px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>FIM Password Hash Generator</h1>
            <p>Generate a secure hash for your FIM admin password.</p>
            
            <?php if (isset($error)): ?>
                <div class="error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <?php if (isset($success)): ?>
                <div class="success">
                    <h3>Password Hash Generated Successfully!</h3>
                    <p>Copy this hash to your <code>fim-config.php</code> file:</p>
                    <div class="hash-output">
                        'admin_password' => '<?php echo htmlspecialchars($hash); ?>',
                    </div>
                </div>
                <div class="warning">
                    <strong>Security Note:</strong> Clear your browser history and delete this file after use.
                </div>
            <?php else: ?>
                <form method="post">
                    <div class="form-group">
                        <label for="password">Admin Password:</label>
                        <input type="password" id="password" name="password" required 
                               placeholder="Enter your desired admin password">
                    </div>
                    <button type="submit" class="btn">Generate Hash</button>
                </form>
            <?php endif; ?>
            
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 14px;">
                <p><strong>Instructions:</strong></p>
                <ol>
                    <li>Enter your desired admin password above</li>
                    <li>Copy the generated hash to your <code>config/fim-config.php</code> file</li>
                    <li>Replace the plain text password with the hash</li>
                    <li>Delete this file for security</li>
                </ol>
            </div>
        </div>
    </body>
    </html>
    <?php
}
?>