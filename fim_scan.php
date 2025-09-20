<?php
// Debug logging - add this right at the start
$debug_log = '/home/greatmai/fim_script_debug.log';
$debug_info = date('Y-m-d H:i:s') . " - Script called\n";
$debug_info .= "REQUEST_METHOD: " . ($_SERVER['REQUEST_METHOD'] ?? 'Not set') . "\n";
$debug_info .= "HTTP_HOST: " . ($_SERVER['HTTP_HOST'] ?? 'Not set') . "\n";
$debug_info .= "REQUEST_URI: " . ($_SERVER['REQUEST_URI'] ?? 'Not set') . "\n";
$debug_info .= "USER_AGENT: " . ($_SERVER['HTTP_USER_AGENT'] ?? 'Not set') . "\n";
$debug_info .= "REMOTE_ADDR: " . ($_SERVER['REMOTE_ADDR'] ?? 'Not set') . "\n";
$debug_info .= "GET params: " . print_r($_GET, true);
$debug_info .= "POST params: " . print_r($_POST, true);
$debug_info .= "php_sapi_name(): " . php_sapi_name() . "\n";
$debug_info .= "Current user: " . get_current_user() . "\n";
$debug_info .= "---\n";
file_put_contents($debug_log, $debug_info, FILE_APPEND | LOCK_EX);

/**
 * File Integrity Monitor (FIM) - Open Source Edition
 * 
 * Monitors file changes across multiple domains/applications
 * Features: SHA256 hashing, configurable exclusions, email alerts, web interface
 * 
 * Requirements: PHP 7.4+, PHPMailer (optional, for SMTP)
 * 
 * @author Your Name
 * @version 2.0
 * @license MIT
 */

date_default_timezone_set('America/New_York'); // Add this line
ini_set('error_reporting', E_ALL);
ini_set('display_errors', 1);

// Disable PHP mail logging to prevent read-only filesystem errors
ini_set('mail.log', '');
ini_set('log_errors_max_len', 0);
// Suppress mail() function warnings about log files
error_reporting(E_ALL & ~E_WARNING);

// Load configuration
$config_file = __DIR__ . '/config/fim-config.php';
if (!file_exists($config_file)) {
    die("Configuration file not found. Please copy config/fim-config.php.example to config/fim-config.php and configure it.");
}
$config = require $config_file;

// Security check with configurable access key
$verifyParam = $_GET['verify'] ?? $_POST['verify'] ?? '';
if ($verifyParam !== $config['security']['access_key']) {
    header('HTTP/1.1 403 Forbidden');
    echo "This script must be run with proper authorization.";
    exit(1);
}

// Start session for admin authentication
session_start();

// Initialize variables
$isAdmin = false;
$updateBaseline = false;
$pagemessage = '';
$pagemessage2 = '';
$authError = '';
$emailDebug = ''; // Add debug info

// Simple authentication system with secure password hashing
function authenticateAdmin($config) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        
        if ($username === $config['security']['admin_username'] && 
            password_verify($password, $config['security']['admin_password'])) {
            $_SESSION['fim_admin'] = true;
            $_SESSION['fim_login_time'] = time();
            return true;
        } else {
            return false;
        }
    }
    
    // Check existing session
    if (isset($_SESSION['fim_admin']) && $_SESSION['fim_admin'] === true) {
        $sessionAge = time() - ($_SESSION['fim_login_time'] ?? 0);
        if ($sessionAge < ($config['security']['session_timeout'] * 60)) {
            return true;
        } else {
            // Session expired
            unset($_SESSION['fim_admin']);
            unset($_SESSION['fim_login_time']);
        }
    }
    
    return false;
}

// Handle logout
if (isset($_GET['logout'])) {
    unset($_SESSION['fim_admin']);
    unset($_SESSION['fim_login_time']);
    header("Location: " . $_SERVER['PHP_SELF'] . "?verify=" . $config['security']['access_key']);
    exit();
}

// Check admin authentication
$isAdmin = authenticateAdmin($config);

// Handle login attempt
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login']) && !$isAdmin) {
    $authError = "Invalid username or password.";
}

// Check if this is a baseline update request (POST from admin form)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_baseline']) && $_POST['update_baseline'] === 'true' && $isAdmin) {
    $updateBaseline = true;
}

// Check if admin requested a manual scan
$manualScan = ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['run_scan']) && $isAdmin);

// Determine if this is a cron run or web access
//$isCronRun = (php_sapi_name() === 'cli' || !isset($_SERVER['HTTP_HOST']));
$isCronRun = (php_sapi_name() === 'cli' || 
              !isset($_SERVER['HTTP_HOST']) ||
              (isset($_GET['cron']) && $_GET['cron'] === '1'));




// Only proceed with scan if we have valid access (either cron or authenticated admin with explicit request)
$runScan = false;
if ($isCronRun) {
    // Always run for cron jobs
    $runScan = true;
} elseif ($isAdmin && ($updateBaseline || $manualScan)) {
    // Only run for authenticated web users who explicitly request it
    $runScan = true;
}

// Import PHPMailer classes
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Load PHPMailer (only needed if SMTP is enabled)
if (($config['email']['use_smtp'] ?? false) === true) {
    if (file_exists(__DIR__ . '/vendor/autoload.php')) {
        require __DIR__ . '/vendor/autoload.php';
    } else {
        // Fallback to manual includes
        if (file_exists(__DIR__ . '/PHPMailer/src/Exception.php')) {
            require_once __DIR__ . '/PHPMailer/src/Exception.php';
            require_once __DIR__ . '/PHPMailer/src/PHPMailer.php';
            require_once __DIR__ . '/PHPMailer/src/SMTP.php';
        } else {
            die("SMTP enabled but PHPMailer not found. Please install PHPMailer or set 'use_smtp' to false.");
        }
    }
}

// Initialize results
$scan_results = [
    'timestamp' => date('Y-m-d H:i:s'),
    'domains' => [],
    'summary' => [
        'total_files' => 0,
        'changed_files' => 0,
        'new_files' => 0,
        'deleted_files' => 0,
        'domains_scanned' => 0,
        'enabled_domains' => 0
    ]
];

// Create FIM directories if they don't exist
$baselinePath = rtrim($config['monitoring']['baseline_path'], '/') . '/';
$logPath = rtrim($config['monitoring']['log_path'], '/') . '/';

if (!is_dir($baselinePath)) {
    mkdir($baselinePath, 0755, true);
}
if (!is_dir($logPath)) {
    mkdir($logPath, 0755, true);
}

// Helper function to check if file should be excluded
function shouldExcludeFile($filePath, $excludePatterns) {
    foreach ($excludePatterns as $pattern) {
        if (preg_match($pattern, $filePath)) {
            return true;
        }
    }
    return false;
}

// Helper function to scan directory and calculate hashes
function scanDirectoryForHashes($path, $excludePatterns, $hashAlgorithm) {
    $hashes = [];
    
    if (!is_dir($path)) {
        return $hashes;
    }
    
    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
        
        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $relativePath = str_replace($path, '', $file->getPathname());
                
                // Skip excluded files
                if (shouldExcludeFile($relativePath, $excludePatterns)) {
                    continue;
                }
                
                $hashes[$relativePath] = [
                    'hash' => hash_file($hashAlgorithm, $file->getPathname()),
                    'size' => $file->getSize(),
                    'modified' => $file->getMTime()
                ];
            }
        }
    } catch (Exception $e) {
        // Handle permission errors gracefully
        error_log("FIM: Error scanning directory $path: " . $e->getMessage());
    }
    
    return $hashes;
}

// Helper function to compare hashes
function compareHashes($current, $baseline) {
    $changes = [
        'new' => [],
        'modified' => [],
        'deleted' => []
    ];
    
    // Find new and modified files
    foreach ($current as $file => $data) {
        if (!isset($baseline[$file])) {
            $changes['new'][] = $file;
        } elseif ($baseline[$file]['hash'] !== $data['hash']) {
            $changes['modified'][] = [
                'file' => $file,
                'old_hash' => substr($baseline[$file]['hash'], 0, 8),
                'new_hash' => substr($data['hash'], 0, 8),
                'size_change' => $data['size'] - $baseline[$file]['size']
            ];
        }
    }
    
    // Find deleted files
    foreach ($baseline as $file => $data) {
        if (!isset($current[$file])) {
            $changes['deleted'][] = $file;
        }
    }
    
    return $changes;
}

// Main scanning process
if ($runScan) {
    $startTime = microtime(true);
    $baselineUpdatesPerformed = [];
    
    foreach ($config['domains'] as $domainKey => $domainConfig) {
        // Skip disabled domains
        if (!isset($domainConfig['enabled']) || !$domainConfig['enabled']) {
            continue;
        }
        
        $scan_results['summary']['enabled_domains']++;
        
        if (!is_dir($domainConfig['path'])) {
            $scan_results['domains'][$domainKey] = [
                'error' => 'Path not found: ' . $domainConfig['path']
            ];
            continue;
        }
        
        // Scan current files
        $currentHashes = scanDirectoryForHashes(
            $domainConfig['path'], 
            $domainConfig['exclude_patterns'], 
            $config['monitoring']['hash_algorithm']
        );
        
        // Load baseline
        $baselineFile = $baselinePath . $domainKey . '_baseline.json';
        $baselineHashes = [];
        if (file_exists($baselineFile)) {
            $content = file_get_contents($baselineFile);
            $baselineHashes = json_decode($content, true) ?: [];
        }
        
        // Compare hashes
        $changes = compareHashes($currentHashes, $baselineHashes);
        
        // Store results
        $scan_results['domains'][$domainKey] = [
            'name' => $domainConfig['name'],
            'path' => $domainConfig['path'],
            'files_scanned' => count($currentHashes),
            'changes' => $changes,
            'baseline_updated' => false
        ];
        
        // Update summary
        $scan_results['summary']['total_files'] += count($currentHashes);
        $scan_results['summary']['changed_files'] += count($changes['modified']);
        $scan_results['summary']['new_files'] += count($changes['new']);
        $scan_results['summary']['deleted_files'] += count($changes['deleted']);
        $scan_results['summary']['domains_scanned']++;
        
        // Save baseline if first run OR if baseline update requested
        $shouldUpdateBaseline = empty($baselineHashes) || $updateBaseline;
        
        if ($shouldUpdateBaseline) {
            $jsonData = json_encode($currentHashes, JSON_PRETTY_PRINT);
            $writeResult = file_put_contents($baselineFile, $jsonData);
            
            if ($writeResult !== false) {
                $scan_results['domains'][$domainKey]['baseline_updated'] = true;
                $baselineUpdatesPerformed[] = $domainConfig['name'];
                
                if ($updateBaseline) {
                    $scan_results['domains'][$domainKey]['update_note'] = 'Updated by admin - ' . count($currentHashes) . ' files';
                } else {
                    $scan_results['domains'][$domainKey]['update_note'] = 'Initial baseline created - ' . count($currentHashes) . ' files';
                }
            } else {
                $scan_results['domains'][$domainKey]['update_error'] = 'Failed to write baseline file';
            }
        }
    }
    
    $scan_results['execution_time'] = round(microtime(true) - $startTime, 2);
    
    // Add baseline update summary if performed
    if (!empty($baselineUpdatesPerformed)) {
        $scan_results['baseline_update_summary'] = [
            'updated_domains' => $baselineUpdatesPerformed,
            'update_timestamp' => date('Y-m-d H:i:s'),
            'triggered_by' => $updateBaseline ? 'admin_request' : 'initial_setup'
        ];
    }
    
    // Log results
    $logFile = $logPath . 'fim_' . date('Y-m') . '.log';
    $logEntry = date('Y-m-d H:i:s') . " - " . json_encode($scan_results) . "\n";
    file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
    
    // Check if we have changes (only check if NOT updating baseline)
    $hasChanges = false;
    if (!$updateBaseline) {
        $hasChanges = ($scan_results['summary']['changed_files'] > 0 || 
                      $scan_results['summary']['new_files'] > 0 || 
                      $scan_results['summary']['deleted_files'] > 0);
    }
    
    // Determine if email should be sent
    $shouldSendEmail = false;
    $emailReason = '';
    
    if ($updateBaseline) {
        $shouldSendEmail = true;
        $emailReason = 'baseline_update';
        $pagemessage = "Baseline Update Completed Successfully!";
    } elseif ($hasChanges) {
        $shouldSendEmail = true;
        $emailReason = 'changes_detected';
        $pagemessage = "File Integrity Alert - Changes Detected!";
    } elseif ($config['monitoring']['email_on_clean_scan']) {
        $shouldSendEmail = true;
        $emailReason = 'clean_scan';
        $pagemessage = "File Integrity Check Complete - No Changes Detected";
    } else {
        $pagemessage = "File Integrity Check Complete - No Changes Detected (Email skipped)";
        $emailReason = 'skipped_clean_scan';
    }
    
    $emailDebug = "Email Decision: shouldSendEmail=" . ($shouldSendEmail ? 'true' : 'false') . ", reason=" . $emailReason . "\n";
    
    // Email sending logic - SIMPLIFIED AND CONSOLIDATED
    if ($shouldSendEmail) {
        $emailDebug .= "Attempting to send email...\n";
        
        // Build email content once
        if ($updateBaseline) {
            $domainNames = array_map(function($name) { return $name; }, $baselineUpdatesPerformed);
            $subject = "FIM Baseline Updated - " . implode(', ', $domainNames) . " on " . date('Y-m-d H:i:s');
            $message = "File Integrity Monitoring - Baseline Update Completed\n";
            $message .= "Update completed: " . $scan_results['timestamp'] . "\n\n";
            $message .= "Updated domains: " . implode(', ', $domainNames) . "\n";
            $message .= "Total files now in baseline: " . $scan_results['summary']['total_files'] . "\n\n";
            $message .= "All previously detected changes have been accepted into the new baseline.\n";
            $message .= "Future scans will compare against this updated baseline.\n";
        } elseif ($hasChanges) {
            // Get list of domains that have changes
            $domainsWithChanges = [];
            foreach ($scan_results['domains'] as $domain => $data) {
                if (!empty($data['changes']['modified']) || !empty($data['changes']['new']) || !empty($data['changes']['deleted'])) {
                    $domainsWithChanges[] = $data['name'];
                }
            }
            $domainList = !empty($domainsWithChanges) ? implode(', ', $domainsWithChanges) : 'Multiple Domains';
            
            $subject = "File Integrity Alert - " . $domainList . " - Changes Detected on " . date('Y-m-d H:i:s');
            $message = "File Integrity Monitoring Alert\n";
            $message .= "Scan completed: " . $scan_results['timestamp'] . "\n";
            $message .= "Affected domains: " . $domainList . "\n\n";
            $message .= "Summary:\n";
            $message .= "- Modified files: " . $scan_results['summary']['changed_files'] . "\n";
            $message .= "- New files: " . $scan_results['summary']['new_files'] . "\n";
            $message .= "- Deleted files: " . $scan_results['summary']['deleted_files'] . "\n\n";
            
            foreach ($scan_results['domains'] as $domain => $data) {
                if (!empty($data['changes']['modified']) || !empty($data['changes']['new']) || !empty($data['changes']['deleted'])) {
                    $message .= "Domain: " . $data['name'] . " (" . $data['path'] . ")\n";
                    
                    if (!empty($data['changes']['modified'])) {
                        $message .= "Modified files:\n";
                        foreach ($data['changes']['modified'] as $change) {
                            $message .= "  - " . $change['file'] . " (size change: " . $change['size_change'] . " bytes)\n";
                        }
                    }
                    
                    if (!empty($data['changes']['new'])) {
                        $message .= "New files:\n";
                        foreach ($data['changes']['new'] as $file) {
                            $message .= "  - " . $file . "\n";
                        }
                    }
                    
                    if (!empty($data['changes']['deleted'])) {
                        $message .= "Deleted files:\n";
                        foreach ($data['changes']['deleted'] as $file) {
                            $message .= "  - " . $file . "\n";
                        }
                    }
                    $message .= "\n";
                }
            }
            
            $message .= "Please review these changes and update the baseline if they are legitimate.\n";
            $message .= "Admin panel: " . (isset($_SERVER['HTTP_HOST']) ? 
                "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'] . "?verify=" . $config['security']['access_key'] : 
                "Run via web interface") . "\n";
        } else {
            // Get list of all scanned domains for clean scan email
            $scannedDomains = [];
            foreach ($scan_results['domains'] as $domain => $data) {
                if (isset($data['name'])) {
                    $scannedDomains[] = $data['name'];
                }
            }
            $domainList = !empty($scannedDomains) ? implode(', ', $scannedDomains) : 'All Domains';
            
            $subject = "File Integrity Monitor - " . $domainList . " - All Clear on " . date('Y-m-d H:i:s');
            $message = "File Integrity Monitoring Report\n";
            $message .= "Scan completed: " . $scan_results['timestamp'] . "\n";
            $message .= "Scanned domains: " . $domainList . "\n\n";
            $message .= "Status: No changes detected - All files secure\n\n";
            $message .= "Summary:\n";
            $message .= "- Domains scanned: " . $scan_results['summary']['domains_scanned'] . "\n";
            $message .= "- Total files monitored: " . $scan_results['summary']['total_files'] . "\n";
            $message .= "- Execution time: " . $scan_results['execution_time'] . " seconds\n";
        }
        
        $emailDebug .= "Subject: " . $subject . "\n";
        $emailDebug .= "Message length: " . strlen($message) . " characters\n";
        
        try {
            // Check if SMTP is enabled
            $useSmtp = ($config['email']['use_smtp'] ?? false) === true;
            $emailDebug .= "Email method: " . ($useSmtp ? 'SMTP' : 'PHP mail()') . "\n";
            
            if ($useSmtp) {
                // Use PHPMailer for SMTP
                $mail = new PHPMailer(true);
                
                // Server settings
                $mail->isSMTP();
                $mail->Host       = $config['email']['smtp_host'];
                $mail->SMTPAuth   = true;
                $mail->Username   = $config['email']['smtp_username'];
                $mail->Password   = $config['email']['smtp_password'];
                $mail->SMTPSecure = $config['email']['smtp_encryption'];
                $mail->Port       = $config['email']['smtp_port'];
                
                // Recipients
                $mail->setFrom($config['email']['from_email'], $config['email']['from_name']);
                $mail->addAddress($config['email']['to_email']);
                
                // Content
                $mail->isHTML(false);
                $mail->Subject = $subject;
                $mail->Body = $message;
                
                $mail->send();
                $pagemessage2 = "Status email sent via SMTP to " . $config['email']['to_email'];
                $emailDebug .= "SMTP email sent successfully\n";
            } else {
                // Use PHP's built-in mail() function
                $emailDebug .= "Using PHP mail() function\n";
                $emailDebug .= "To: " . $config['email']['to_email'] . "\n";
                $emailDebug .= "From: " . $config['email']['from_email'] . "\n";
                
                $headers = array();
                $headers[] = 'From: ' . $config['email']['from_name'] . ' <' . $config['email']['from_email'] . '>';
                $headers[] = 'Reply-To: ' . $config['email']['from_email'];
                $headers[] = 'X-Mailer: File Integrity Monitor';
                $headers[] = 'Content-Type: text/plain; charset=UTF-8';
                
                $emailDebug .= "Headers: " . implode("; ", $headers) . "\n";
                
                // Suppress warnings for mail() function specifically
                $success = @mail(
                    $config['email']['to_email'],
                    $subject,
                    $message,
                    implode("\r\n", $headers)
                );
                
                $emailDebug .= "mail() function returned: " . ($success ? 'true' : 'false') . "\n";
                
                if ($success) {
                    $pagemessage2 = "Status email sent via PHP mail to " . $config['email']['to_email'];
                    $emailDebug .= "PHP mail sent successfully\n";
                } else {
                    $pagemessage2 = "Failed to send email via PHP mail - check server configuration";
                    $emailDebug .= "PHP mail failed - check server mail configuration\n";
                    
                    // Try to get more error info
                    $lastError = error_get_last();
                    if ($lastError) {
                        $emailDebug .= "Last PHP error: " . $lastError['message'] . "\n";
                    }
                }
            }
        } catch (Exception $e) {
            $pagemessage2 = "Status email could not be sent. Error: " . $e->getMessage();
            $emailDebug .= "Exception caught: " . $e->getMessage() . "\n";
        }
    } else {
        $emailDebug .= "Email not sent - conditions not met\n";
    }
    
    // Log email debug info
    $emailLogEntry = date('Y-m-d H:i:s') . " EMAIL DEBUG:\n" . $emailDebug . "\n";
    file_put_contents($logPath . 'email_debug_' . date('Y-m') . '.log', $emailLogEntry, FILE_APPEND | LOCK_EX);
}

// If running from command line, just exit after scan
if ($isCronRun) {
    if ($runScan) {
        echo "FIM scan completed at " . date('Y-m-d H:i:s') . "\n";
        echo "Summary: " . $scan_results['summary']['total_files'] . " files, " . 
             $scan_results['summary']['changed_files'] . " changed, " . 
             $scan_results['summary']['new_files'] . " new, " . 
             $scan_results['summary']['deleted_files'] . " deleted\n";
        echo "Email Debug Info:\n" . $emailDebug;
    }
    exit(0);
}

?>
<!DOCTYPE html>
<html>
<head>
    <title>File Integrity Monitor</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
		.header { border-bottom: 2px solid #007cba; padding-bottom: 25px; margin-bottom: 20px; }
        .success-message { background: #d4edda; color: #155724; padding: 15px; border: 1px solid #c3e6cb; border-radius: 4px; margin: 15px 0; }
        .alert-message { background: #fff3cd; color: #856404; padding: 15px; border: 1px solid #ffc107; border-radius: 4px; margin: 15px 0; }
        .info-message { background: #d1ecf1; color: #0c5460; padding: 15px; border: 1px solid #bee5eb; border-radius: 4px; margin: 15px 0; }
        .error-message { background: #f8d7da; color: #721c24; padding: 15px; border: 1px solid #f5c6cb; border-radius: 4px; margin: 15px 0; }
        .login-form { max-width: 400px; margin: 50px auto; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; text-decoration: none; display: inline-block; }
        .btn-primary { background: #007cba; color: white; }
        .btn-success { background: #28a745; color: white; }
        .btn-danger { background: #dc3545; color: white; }
        .btn:hover { opacity: 0.9; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 15px; border-radius: 4px; text-align: center; }
        .stat-number { font-size: 24px; font-weight: bold; color: #007cba; }
        .stat-label { color: #666; margin-top: 5px; }
        .domain-section { border: 1px solid #dee2e6; border-radius: 4px; margin: 15px 0; }
        .domain-header { background: #f8f9fa; padding: 15px; border-bottom: 1px solid #dee2e6; font-weight: bold; }
        .domain-content { padding: 15px; }
        .changes-list { background: #f8f9fa; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .changes-list ul { margin: 5px 0; padding-left: 20px; }
		.logout-link { float: right; color: #666; text-decoration: none; font-size: 14px; }
        .logout-link:hover { color: #333; }
    </style>
</head>
<body>

<?php if (!$isAdmin): ?>
    <div class="login-form">
        <h2>File Integrity Monitor - Admin Login</h2>
        <?php if ($authError): ?>
            <div class="error-message"><?php echo htmlspecialchars($authError); ?></div>
        <?php endif; ?>
        <form method="post">
            <input type="hidden" name="verify" value="<?php echo htmlspecialchars($config['security']['access_key']); ?>">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" name="login" class="btn btn-primary" style="width: 100%;">Login</button>
        </form>
        <p style="text-align: center; margin-top: 20px; color: #666; font-size: 14px;">
            File Integrity Monitor v2.0<br>
            Scan runs automatically via cron
        </p>
    </div>
<?php else: ?>

<div class="container">
    <div class="header">
        <h1>File Integrity Monitor</h1>
        <a href="?verify=<?php echo htmlspecialchars($config['security']['access_key']); ?>&logout=1" class="logout-link">Logout</a>
    </div>

    <?php if ($pagemessage): ?>
        <div class="info-message">
            <h3><?php echo htmlspecialchars($pagemessage); ?></h3>
            <?php if ($pagemessage2): ?>
                <p><?php echo htmlspecialchars($pagemessage2); ?></p>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php if ($updateBaseline && !empty($baselineUpdatesPerformed)): ?>
        <div class="success-message">
            <h3>✓ Baseline Successfully Updated!</h3>
            <p>The baseline has been updated for: <strong><?php echo implode(', ', $baselineUpdatesPerformed); ?></strong></p>
            <p>All previously detected changes have been accepted. Future scans will use this new baseline.</p>
        </div>
    <?php endif; ?>

    <!-- SCAN RESULTS SECTION FIRST -->
    <?php if ($runScan): ?>
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number"><?php echo $scan_results['summary']['domains_scanned']; ?></div>
                <div class="stat-label">Domains Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><?php echo number_format($scan_results['summary']['total_files']); ?></div>
                <div class="stat-label">Total Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: <?php echo $scan_results['summary']['changed_files'] > 0 ? '#dc3545' : '#28a745'; ?>">
                    <?php echo $scan_results['summary']['changed_files']; ?>
                </div>
                <div class="stat-label">Modified Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: <?php echo $scan_results['summary']['new_files'] > 0 ? '#ffc107' : '#28a745'; ?>">
                    <?php echo $scan_results['summary']['new_files']; ?>
                </div>
                <div class="stat-label">New Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: <?php echo $scan_results['summary']['deleted_files'] > 0 ? '#dc3545' : '#28a745'; ?>">
                    <?php echo $scan_results['summary']['deleted_files']; ?>
                </div>
                <div class="stat-label">Deleted Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><?php echo $scan_results['execution_time']; ?>s</div>
                <div class="stat-label">Execution Time</div>
            </div>
        </div>

        <?php 
        $hasChanges = ($scan_results['summary']['changed_files'] > 0 || 
                      $scan_results['summary']['new_files'] > 0 || 
                      $scan_results['summary']['deleted_files'] > 0);
        ?>

        <?php if ($hasChanges && !$updateBaseline): ?>
            <div class="alert-message">
                <h3>⚠ Changes Detected - Review Required</h3>
                <p>File changes have been detected. Please review the changes below and click "Accept Changes" if they are legitimate.</p>
                <form method="post" onsubmit="return confirm('Are you sure these changes are legitimate and should be accepted into the baseline?');">
                    <input type="hidden" name="verify" value="<?php echo htmlspecialchars($config['security']['access_key']); ?>">
                    <input type="hidden" name="update_baseline" value="true">
                    <button type="submit" class="btn btn-success">✓ Accept Changes & Update Baseline</button>
                </form>
            </div>
        <?php elseif (!$updateBaseline): ?>
            <div class="success-message">
                <h3>✓ No Action Required</h3>
                <p>No file changes detected. All monitored files match the current baseline.</p>
            </div>
        <?php endif; ?>

        <h2>Domain Scan Results</h2>
        <p><strong>Last scan:</strong> <?php echo $scan_results['timestamp']; ?></p>

        <?php if (empty($scan_results['domains'])): ?>
            <div class="info-message">
                <p>No domains are currently enabled for monitoring. Please check your configuration file and enable at least one domain.</p>
            </div>
        <?php else: ?>
            <?php foreach ($scan_results['domains'] as $domainKey => $domainData): ?>
                <div class="domain-section">
                    <div class="domain-header">
                        <?php if (isset($domainData['error'])): ?>
                            <?php echo htmlspecialchars($domainKey); ?> - ERROR
                        <?php else: ?>
                            <?php echo htmlspecialchars($domainData['name']); ?>
                        <?php endif; ?>
                    </div>
                    <div class="domain-content">
                        <?php if (isset($domainData['error'])): ?>
                            <div class="error-message">
                                <strong>Error:</strong> <?php echo htmlspecialchars($domainData['error']); ?>
                            </div>
                        <?php else: ?>
                            <p><strong>Path:</strong> <?php echo htmlspecialchars($domainData['path']); ?></p>
                            <p><strong>Files scanned:</strong> <?php echo number_format($domainData['files_scanned']); ?></p>
                            
                            <?php if ($domainData['baseline_updated']): ?>
                                <div class="success-message">
                                    <strong>✓ Baseline updated for this domain</strong>
                                    <?php if (isset($domainData['update_note'])): ?>
                                        <br><?php echo htmlspecialchars($domainData['update_note']); ?>
                                    <?php endif; ?>
                                </div>
                            <?php endif; ?>
                            
                            <?php if (isset($domainData['update_error'])): ?>
                                <div class="error-message">
                                    <strong>✗ Error:</strong> <?php echo htmlspecialchars($domainData['update_error']); ?>
                                </div>
                            <?php endif; ?>
                            
                            <?php
                            $totalChanges = count($domainData['changes']['modified']) + 
                                           count($domainData['changes']['new']) + 
                                           count($domainData['changes']['deleted']);
                            ?>
                            
                            <?php if ($totalChanges > 0): ?>
                                <div class="alert-message">
                                    <strong>Changes detected: <?php echo $totalChanges; ?></strong>
                                </div>
                                
                                <?php if (!empty($domainData['changes']['new'])): ?>
                                    <div class="changes-list">
                                        <strong>New files (<?php echo count($domainData['changes']['new']); ?>):</strong>
                                        <ul>
                                        <?php foreach ($domainData['changes']['new'] as $file): ?>
                                            <li><?php echo htmlspecialchars($file); ?></li>
                                        <?php endforeach; ?>
                                        </ul>
                                    </div>
                                <?php endif; ?>
                                
                                <?php if (!empty($domainData['changes']['modified'])): ?>
                                    <div class="changes-list">
                                        <strong>Modified files (<?php echo count($domainData['changes']['modified']); ?>):</strong>
                                        <ul>
                                        <?php foreach ($domainData['changes']['modified'] as $change): ?>
                                            <li><?php echo htmlspecialchars($change['file']); ?> 
                                                (size change: <?php echo $change['size_change']; ?> bytes)</li>
                                        <?php endforeach; ?>
                                        </ul>
                                    </div>
                                <?php endif; ?>
                                
                                <?php if (!empty($domainData['changes']['deleted'])): ?>
                                    <div class="changes-list">
                                        <strong>Deleted files (<?php echo count($domainData['changes']['deleted']); ?>):</strong>
                                        <ul>
                                        <?php foreach ($domainData['changes']['deleted'] as $file): ?>
                                            <li><?php echo htmlspecialchars($file); ?></li>
                                        <?php endforeach; ?>
                                        </ul>
                                    </div>
                                <?php endif; ?>
                            <?php else: ?>
                                <div class="success-message">
                                    <strong>✓ No changes detected</strong>
                                </div>
                            <?php endif; ?>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; ?>
        <?php endif; ?>
    <?php endif; ?>

    <!-- MANUAL SCAN CONTROL SECTION - NOW MOVED TO AFTER RESULTS -->
    <?php if ($isAdmin): ?>
        <div class="info-message">
            <?php if (!$runScan): ?>
                <h3>Scan Status</h3>
                <p>File integrity scan has not been run in this session. Scans run automatically via cron job.</p>
                <p>To manually trigger a scan and view current results, click the button below:</p>
            <?php elseif ($updateBaseline): ?>
                <h3>Baseline Updated Successfully</h3>
                <p>Baseline update completed: <strong><?php echo $scan_results['timestamp']; ?></strong></p>
                <p>Run another scan to verify the new baseline or check for additional changes:</p>
            <?php else: ?>
                <h3>Manual Scan Control</h3>
                <p>Last scan completed: <strong><?php echo $scan_results['timestamp']; ?></strong></p>
                <p>Trigger another scan to refresh results or verify recent changes:</p>
            <?php endif; ?>
            <form method="post" style="margin-top: 15px;">
                <input type="hidden" name="verify" value="<?php echo htmlspecialchars($config['security']['access_key']); ?>">
                <input type="hidden" name="run_scan" value="true">
                <button type="submit" class="btn btn-primary">
                    <?php if (!$runScan): ?>
                        🔍 Run Manual Scan
                    <?php elseif ($updateBaseline): ?>
                        🔄 Run Post-Update Scan
                    <?php else: ?>
                        🔄 Run Another Scan
                    <?php endif; ?>
                </button>
            </form>
        </div>
    <?php endif; ?>

    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #666; font-size: 14px;">
        <p><strong>File Integrity Monitor v2.0</strong> - Open Source Edition</p>
        <p>Configure scheduled scans via cron for automated monitoring. Access this interface to review alerts and update baselines.</p>
    </div>
</div>

<?php endif; ?>

</body>
</html>