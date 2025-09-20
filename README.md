# File Integrity Monitor (FIM) - Open Source Edition

A powerful, lightweight PHP-based File Integrity Monitoring system that detects unauthorized changes to your web applications and servers. Perfect for WordPress sites, Laravel applications, e-commerce platforms, and any PHP-based web application.

## Features

- **Zero Database Required** - File-based storage using JSON baselines
- **Multi-Domain Support** - Monitor multiple websites/applications from one installation
- **Configurable Exclusions** - Comprehensive pattern-based file exclusion system
- **Email Alerts** - SMTP notifications for changes, clean scans, and baseline updates
- **Web Interface** - Secure admin panel to review changes and update baselines
- **Cron Ready** - Designed for automated scheduled scanning
- **WordPress Optimized** - Pre-configured exclusion patterns for WordPress installations
- **Framework Support** - Includes exclusion examples for Laravel, general PHP apps, and e-commerce sites
- **SHA256 Hashing** - Cryptographically secure file integrity verification
- **Performance Optimized** - Efficient recursive directory scanning with configurable exclusions

## Requirements

- PHP 7.4 or higher
- Web server (Apache/Nginx) for admin interface
- Cron access for scheduled scanning
- **Email Method Options:**
  - **PHP Mail** (default) - Built into PHP, no additional setup required
  - **SMTP** (optional) - Requires PHPMailer, more reliable delivery

## Installation

### Option 1: Quick Start (PHP Mail)

1. **Download and extract** this repository to your server
2. **Generate secure admin password:**
   
   php hash_password.php
   
   Or via web interface: https://yourdomain.com/path/to/hash_password.php
   
3. **Copy the configuration file:**
   
   cp config/fim-config.php.example config/fim-config.php
   
4. **Edit configuration** - set email addresses, paste your password hash, and enable domains
5. **Delete the password utility** for security:
   
   rm hash_password.php
   
6. **Set up cron job** (see Cron Setup Examples below)

### Option 2: Enhanced Setup (SMTP Email)

1. **Install PHPMailer** via Composer:
   
   composer install
   
2. **Generate secure admin password:**
   
   php hash_password.php
   
3. **Configure as above**, but set email method to 'smtp' and add SMTP settings
4. **Delete the password utility** for security:
   
   rm hash_password.php
   
5. **Set up cron job** (see Cron Setup Examples below)

## Configuration

Edit config/fim-config.php to customize your installation:

### Security Settings

'security' => [
    'access_key' => 'your-random-access-key-here',  // Change this!
    'admin_username' => 'admin',                     // Change this!
    'admin_password' => '$2y$10$hash...',            // Generated via hash_password.php
    'session_timeout' => 60                          // Minutes
]

**Important**: Always use the hash_password.php utility to generate secure password hashes. Never store plain text passwords in the configuration file.

### Email Configuration

'email' => [
    'from_email' => 'fim@yourdomain.com',
    'to_email' => 'admin@yourdomain.com',
    'from_name' => 'File Integrity Monitor',
    
    // SMTP Settings (when PHPMailer is available)
    'use_smtp' => false,  // Set to true to use SMTP
    'smtp_host' => 'your-smtp-server.com',
    'smtp_port' => 465,
    'smtp_encryption' => 'ssl',
    'smtp_username' => 'your-email@domain.com',
    'smtp_password' => 'your-email-password'
]

### Enable Monitoring for Your Sites

'domains' => [
    'my_wordpress_site' => [
        'name' => 'My WordPress Site',
        'path' => '/var/www/html/',
        'enabled' => true,  // Set to true to enable
        'exclude_patterns' => [
            // Pre-configured WordPress exclusions included
        ]
    ]
]

## Pre-Configured Exclusion Patterns

The system includes optimized exclusion patterns for:

### WordPress Sites
- Core directories (wp-admin/, wp-includes/)
- Media uploads (images, videos, documents)
- Cache directories (W3TC, LiteSpeed, WP Rocket, etc.)
- Update and temporary directories
- Log files and debug files
- Database backups

### Laravel Applications
- Storage directories (storage/logs/, storage/cache/)
- Vendor directory and node modules
- Bootstrap cache
- Build files and assets

### E-commerce Platforms
- Product images and media
- Generated PDFs and invoices
- Cache and session directories
- Temporary files

### General PHP Applications
- Common cache and log directories
- Upload directories for user content
- Session files
- Vendor/library directories

## Usage

### Web Interface Access
Visit: https://yourdomain.com/path/to/fim_scan.php?verify=your-access-key

### Command Line Usage

# Manual scan (CLI method)
php fim_scan.php

# Manual scan (web method with access key)
curl -s "https://yourdomain.com/path/to/fim_scan.php?verify=your-access-key"

### Cron Setup Examples

**Recommended: Web-based Cron (Most Reliable)**

# Every 15 minutes
*/15 * * * * /usr/bin/curl -s "https://yourdomain.com/path/to/fim_scan.php?verify=your-access-key&cron=1" > /dev/null 2>&1

# Every hour
0 * * * * /usr/bin/curl -s "https://yourdomain.com/path/to/fim_scan.php?verify=your-access-key&cron=1" > /dev/null 2>&1

# Daily at 2 AM
0 2 * * * /usr/bin/curl -s "https://yourdomain.com/path/to/fim_scan.php?verify=your-access-key&cron=1" > /dev/null 2>&1

**Alternative: Direct CLI Execution**

# Every 15 minutes
*/15 * * * * /usr/bin/php /path/to/fim_scan.php > /dev/null 2>&1

# Every hour
0 * * * * /usr/bin/php /path/to/fim_scan.php > /dev/null 2>&1

# Daily at 2 AM
0 2 * * * /usr/bin/php /path/to/fim_scan.php > /dev/null 2>&1

**Why Web-based Cron is Recommended:**
- Works consistently across shared hosting environments
- Maintains the same security model as manual web access
- Better error handling and logging
- Easier to troubleshoot via web server logs
- No PHP CLI path dependencies

## How It Works

1. **Initial Scan**: Creates baseline fingerprints (SHA256 hashes) of all monitored files
2. **Scheduled Monitoring**: Cron job runs periodic scans comparing current state to baseline
3. **Change Detection**: Identifies new, modified, and deleted files
4. **Alert System**: Sends email notifications when changes are detected
5. **Admin Review**: Web interface allows reviewing changes and updating baselines
6. **Baseline Updates**: Accept legitimate changes to prevent future false alerts

## Directory Structure

fim-monitor/
├── fim_scan.php              # Main script
├── config/
│   ├── fim-config.php        # Your configuration
│   └── fim-config.php.example # Configuration template
├── baselines/                # JSON baseline files (auto-created)
├── logs/                     # Scan logs (auto-created)
├── vendor/                   # Composer dependencies
└── README.md

## Security Considerations

- **Secure Access**: Always change default access keys and passwords
- **File Permissions**: Ensure baseline and log directories are not web-accessible
- **HTTPS**: Use HTTPS for web interface access
- **Regular Updates**: Keep PHPMailer and other dependencies updated
- **Log Monitoring**: Review FIM logs regularly for patterns

## WordPress Installation Guide

For WordPress sites, we recommend installing FIM in a dedicated subdirectory for security and maintenance benefits.

### Recommended WordPress Setup

1. **Create FIM directory** inside your WordPress installation:
   
   mkdir /path/to/wordpress/fim
   cd /path/to/wordpress/fim

2. **Upload FIM files** to this directory:
   
   /var/www/html/              <- Your WordPress site
   ├── wp-admin/
   ├── wp-content/
   ├── wp-config.php
   └── fim/                    <- FIM installation
       ├── fim_scan.php
       ├── config/
       ├── baselines/
       └── logs/

3. **Configure monitoring** in config/fim-config.php:
   
   'my_wordpress_site' => [
       'name' => 'My WordPress Site',
       'path' => '/var/www/html/',      // Monitor parent WordPress directory
       'enabled' => true,
       // Pre-configured WordPress exclusions included
   ]

4. **Access admin interface:**
   https://yoursite.com/fim/fim_scan.php?verify=your-access-key

### Why This Approach?

- **Clean separation** - WordPress updates won't affect FIM
- **Easy access** - Web interface available via subdirectory
- **Complete monitoring** - Monitors entire WordPress installation
- **Secure** - FIM files are protected but accessible
- **Maintainable** - Easy to update FIM independently

### Alternative: Outside Web Root

For maximum security, install FIM completely outside the web directory:

# Install FIM outside web root
mkdir /home/user/fim-monitor
# Configure to monitor /var/www/html/ from /home/user/fim-monitor/
# Run via cron only (no web interface)

### Optimal Exclusion Strategy
The included WordPress exclusion patterns balance security monitoring with operational efficiency:

- **Monitor**: Core files, themes, plugins, wp-config.php
- **Exclude**: Media uploads, cache files, logs, temporary files
- **Special Attention**: Any changes to core files or configuration should trigger immediate investigation

### Recommended Cron Frequency
- **High-Security Sites**: Every 15 minutes
- **Standard Sites**: Every hour
- **Low-Traffic Sites**: Every 6 hours

### Common WordPress Scenarios
- **Plugin Updates**: Will trigger alerts - use admin interface to accept legitimate updates
- **Theme Modifications**: Direct file edits will be detected
- **Malware Detection**: Backdoors and injected code will be caught
- **Core Updates**: WordPress core updates will be detected for review

## Troubleshooting

### Permission Issues

# Ensure directories are writable
chmod 755 baselines/ logs/
chown www-data:www-data baselines/ logs/

### Email Not Sending
- Verify SMTP credentials in configuration
- Check PHP error logs
- Test SMTP settings manually

### Large Site Performance
- Optimize exclusion patterns
- Consider monitoring only critical directories
- Adjust cron frequency for large file volumes

### False Positives
- Review and update exclusion patterns
- Use admin interface to accept legitimate changes
- Monitor logs for recurring patterns

## License

MIT License - see LICENSE file for details

## Credits

Developed by **Greatmail LLC** as part of our commitment to open source security solutions.

**File Integrity Monitoring** - A comprehensive approach to detecting unauthorized changes in web applications through cryptographic hashing and automated monitoring.

For professional email security services, visit greatmail.com

---

**If this helped you, please consider starring the repository!**

## Contributing

Contributions welcome! Please read our contributing guidelines and submit pull requests for any improvements.

## Support

- **Documentation**: Check this README and configuration examples
- **Issues**: Report bugs via GitHub issues
- **Community**: Join discussions in the issues section

## Roadmap

- [ ] Dashboard with historical change tracking
- [ ] Webhook integration for Slack/Discord notifications
- [ ] File quarantine system for suspicious changes
- [ ] Integration with popular security plugins
- [ ] Multi-language support
- [ ] API for third-party integrations

---

**File Integrity Monitor** - Keeping your web applications secure, one file at a time.