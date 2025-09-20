<?php
/**
 * File Integrity Monitor Configuration
 * 
 * Copy this file and customize for your environment.
 * Keep this file secure and outside web root if possible.
 */

return [
    // Security Configuration
    'security' => [
        // Change this to a random string for URL access protection
        'access_key' => 'x7k9mP2qR8wN5vL3',
        
        // Admin authentication - change these credentials
        'admin_username' => 'admin',
        'admin_password' => '$2y$10$hash...',            // Generated via hash_password.php
        
        // Session timeout in minutes
        'session_timeout' => 60
    ],
    
    // Email Configuration
    'email' => [
        // Basic email settings
        'from_email' => 'fim@yourdomain.com',
        'to_email' => 'admin@yourdomain.com',
        'from_name' => 'File Integrity Monitor',
        
        // SMTP Settings (when PHPMailer is available)
        'use_smtp' => false,  // Set to true to use SMTP instead of PHP mail()
        'smtp_host' => 'your-smtp-server.com',
        'smtp_port' => 465,
        'smtp_encryption' => 'ssl', // 'ssl' or 'tls'
        'smtp_username' => 'your-email@yourdomain.com',
        'smtp_password' => 'your-email-password'
    ],
    
    // Monitoring Configuration
    'monitoring' => [
        // Hash algorithm to use (sha256, md5, sha1)
        'hash_algorithm' => 'sha256',
        
        // Paths for FIM data storage
        'baseline_path' => './baselines/',
        'log_path' => './logs/',
        
        // Send email on every scan (true) or only when changes detected (false)
        'email_on_clean_scan' => true
    ],
    
    // Domains/Sites to Monitor
    'domains' => [
        // Example: WordPress Site (FIM installed in /fim/ subdirectory)
        'wordpress_site' => [
            'name' => 'My WordPress Site',
            'path' => '/var/www/html/',  // Monitor WordPress root from FIM subdirectory
            'enabled' => false, // Set to true to enable monitoring
            'exclude_patterns' => [
                // WordPress core directories (usually safe to exclude)
                '/wp-admin\//',
                '/wp-includes\//',
                
                // WordPress update and temporary directories
                '/wp-content\/upgrade\//',
                '/wp-content\/updraft\//',
                
                // Media uploads (images, videos, documents)
                '/wp-content\/uploads\/.*\.(jpg|jpeg|png|gif|bmp|webp|svg|ico)$/i',
                '/wp-content\/uploads\/.*\.(mp3|mp4|avi|mov|wmv|flv|wav)$/i',
                '/wp-content\/uploads\/.*\.(pdf|doc|docx|xls|xlsx|zip|rar|tar|gz)$/i',
                
                // WordPress cache directories
                '/wp-content\/cache\//',
                '/wp-content\/w3tc-config\//',
                '/wp-content\/litespeed-cache\//',
                '/wp-content\/et-cache\//',
                '/wp-content\/wp-rocket-config\//',
                
                // Plugin-specific cache directories
                '/wp-content\/plugins\/.*\/cache\//',
                '/wp-content\/plugins\/.*\/logs\//',
                
                // WordPress logs and debug files
                '/wp-content\/debug\.log$/',
                '/wp-content\/.*\.log$/i',
                '/error_log$/',
                
                // Database backups (if stored in wp-content)
                '/wp-content\/.*\.sql$/i',
                '/wp-content\/.*\.sql\.gz$/i',
                '/wp-content\/backups\//',
                
                // Session and temporary files
                '/wp-content\/sessions\//',
                '/\.tmp$/',
                '/\.temp$/',
                '/~.*$/',
                
                // Version control and development files
                '/\.git\//',
                '/\.svn\//',
                '/node_modules\//',
                '/composer\.lock$/',
                
                // FIM script exclusion (if installed in WordPress directory)
                '/fim\//',
                
                // Common temporary/cache file patterns
                '/thumbs\.db$/i',
                '/\.DS_Store$/',
                '/desktop\.ini$/'
            ]
        ],
        
        // Example: Laravel Application
        'laravel_app' => [
            'name' => 'My Laravel App',
            'path' => '/var/www/laravel-app/',
            'enabled' => false, // Set to true to enable monitoring
            'exclude_patterns' => [
                // Laravel storage directories
                '/storage\/logs\//',
                '/storage\/framework\/cache\//',
                '/storage\/framework\/sessions\//',
                '/storage\/framework\/views\//',
                '/storage\/app\/public\/.*\.(jpg|jpeg|png|gif|pdf|zip)$/i',
                
                // Laravel bootstrap cache
                '/bootstrap\/cache\//',
                
                // Vendor directory (Composer packages)
                '/vendor\//',
                
                // Node modules and build files
                '/node_modules\//',
                '/public\/build\//',
                '/public\/hot$/',
                '/mix-manifest\.json$/',
                
                // Environment and config files (monitor these carefully)
                '/\.env\.example$/',
                
                // Log files
                '/\.log$/i',
                '/storage\/.*\.log$/i',
                
                // Temporary files
                '/\.tmp$/',
                '/\.temp$/',
                '/~.*$/'
            ]
        ],
        
        // Example: Generic PHP Application
        'php_app' => [
            'name' => 'My PHP Application',
            'path' => '/var/www/myapp/',
            'enabled' => false, // Set to true to enable monitoring
            'exclude_patterns' => [
                // Common cache directories
                '/cache\//',
                '/tmp\//',
                '/temp\//',
                
                // Upload directories for user content
                '/uploads\/.*\.(jpg|jpeg|png|gif|bmp|webp|svg)$/i',
                '/uploads\/.*\.(mp3|mp4|avi|mov|wmv|pdf|zip|rar)$/i',
                
                // Log files
                '/logs\//',
                '/\.log$/i',
                '/error_log$/',
                
                // Session files
                '/sessions\//',
                '/sess_.*$/',
                
                // Vendor/library directories
                '/vendor\//',
                '/node_modules\//',
                '/bower_components\//',
                
                // Version control
                '/\.git\//',
                '/\.svn\//',
                
                // Development files
                '/\.sass-cache\//',
                '/\.map$/i',
                
                // Temporary files
                '/\.tmp$/',
                '/\.temp$/',
                '/~.*$/',
                '/thumbs\.db$/i',
                '/\.DS_Store$/',
                '/desktop\.ini$/'
            ]
        ],
        
        // Example: E-commerce Site
        'ecommerce_site' => [
            'name' => 'My E-commerce Site',
            'path' => '/var/www/shop/',
            'enabled' => false, // Set to true to enable monitoring
            'exclude_patterns' => [
                // Product images and media
                '/media\/catalog\/product\/.*\.(jpg|jpeg|png|gif|webp)$/i',
                '/images\/products\/.*\.(jpg|jpeg|png|gif|webp)$/i',
                
                // Generated files (PDFs, invoices, etc.)
                '/var\/pdf\//',
                '/var\/invoices\//',
                '/generated\//',
                
                // Cache directories
                '/var\/cache\//',
                '/var\/page_cache\//',
                '/var\/session\//',
                '/cache\//',
                
                // Log files
                '/var\/log\//',
                '/logs\//',
                '/\.log$/i',
                
                // Temporary files
                '/var\/tmp\//',
                '/tmp\//',
                '/\.tmp$/',
                '/\.temp$/',
                
                // Version control
                '/\.git\//',
                '/\.svn\//',
                
                // System files
                '/thumbs\.db$/i',
                '/\.DS_Store$/',
                '/desktop\.ini$/'
            ]
        ]
    ]
];
?>
