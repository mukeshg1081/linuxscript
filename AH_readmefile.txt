# Security Audit and Server Hardening Script

This script automates the security audit and hardening process of Linux servers. It is modular and can be easily deployed across multiple servers to ensure they meet stringent security standards.

## Features

1. **User and Group Audits**
   - Lists all users and groups on the server.
   - Checks for users with UID 0 (root privileges) and reports any non-standard users.
   - Identifies and reports any users without passwords or with weak passwords.

2. **File and Directory Permissions**
   - Scans for files and directories with world-writable permissions.
   - Checks for the presence of .ssh directories and ensures they have secure permissions.
   - Reports any files with SUID or SGID bits set, particularly on executables.

3. **Service Audits**
   - Lists all running services and checks for any unnecessary or unauthorized services.
   - Ensures that critical services (e.g., sshd, iptables) are running and properly configured.
   - Checks that no services are listening on non-standard or insecure ports.

4. **Firewall and Network Security**
   - Verifies that a firewall (e.g., iptables, ufw) is active and configured to block unauthorized access.
   - Reports any open ports and their associated services.
   - Checks for and reports any IP forwarding or other insecure network configurations.

5. **IP and Network Configuration Checks**
   - Identifies whether the server’s IP addresses are public or private.
   - Provides a summary of all IP addresses assigned to the server, specifying which are public and which are private.
   - Ensures that sensitive services (e.g., SSH) are not exposed on public IPs unless required.

6. **Security Updates and Patching**
   - Checks for and reports any available security updates or patches.
   - Ensures that the server is configured to receive and install security updates regularly.

7. **Log Monitoring**
   - Checks for any recent suspicious log entries that may indicate a security breach, such as too many login attempts on SSH.

8. **Server Hardening Steps**
   - Implements SSH key-based authentication and disables password-based login for root.
   - Disables IPv6 if it is not in use.
   - Secures the bootloader by setting a password for GRUB.
   - Implements recommended iptables rules.
   - Configures unattended-upgrades to automatically apply security updates and remove unused packages.

9. **Custom Security Checks**
   - Allows the script to be easily extended with custom security checks based on specific organizational policies or requirements.
   - Includes a configuration file where custom checks can be defined and managed.

10. **Reporting and Alerting**
    - Generates a summary report of the security audit and hardening process, highlighting any issues that need attention.
    - Optionally, configures the script to send email alerts or notifications if critical vulnerabilities or misconfigurations are found.

## Usage

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/security-audit-script.git
   cd security-audit-script
