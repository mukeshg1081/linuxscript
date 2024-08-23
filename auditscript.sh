#!/bin/bash

# Function to list all users and groups
list_users_groups() {
    echo "Listing all users and groups..."
    cat /etc/passwd
    cat /etc/group
}

# Function to check for users with UID 0
check_uid_0_users() {
    echo "Checking for users with UID 0..."
    awk -F: '($3 == "0") {print}' /etc/passwd
}

# Function to identify users without passwords or with weak passwords
check_weak_passwords() {
    echo "Checking for users without passwords or with weak passwords..."
    awk -F: '($2 == "" || $2 == "*") {print $1}' /etc/shadow
}

# Function to scan for world-writable files and directories
scan_world_writable() {
    echo "Scanning for world-writable files and directories..."
    find / -perm -o+w -type f -exec ls -l {} \;
    find / -perm -o+w -type d -exec ls -ld {} \;
}

# Function to check .ssh directory permissions
check_ssh_permissions() {
    echo "Checking .ssh directory permissions..."
    find /home -type d -name ".ssh" -exec ls -ld {} \;
}

# Function to report files with SUID or SGID bits set
report_suid_sgid() {
    echo "Reporting files with SUID or SGID bits set..."
    find / -perm /6000 -type f -exec ls -l {} \;
}

# Function to list all running services
list_running_services() {
    echo "Listing all running services..."
    systemctl list-units --type=service --state=running
}

# Function to check for unnecessary or unauthorized services
check_unnecessary_services() {
    echo "Checking for unnecessary or unauthorized services..."
    # Add your custom checks here
}

# Function to verify firewall status
verify_firewall() {
    echo "Verifying firewall status..."
    ufw status
}

# Function to report open ports and associated services
report_open_ports() {
    echo "Reporting open ports and associated services..."
    netstat -tuln
}

# Function to check IP forwarding
check_ip_forwarding() {
    echo "Checking IP forwarding..."
    sysctl net.ipv4.ip_forward
}

# Function to identify public vs. private IPs
check_ip_addresses() {
    echo "Checking IP addresses..."
    ip addr show
}

# Function to check for security updates
check_security_updates() {
    echo "Checking for security updates..."
    apt-get update && apt-get upgrade -s | grep -i security
}

# Function to check for suspicious log entries
check_suspicious_logs() {
    echo "Checking for suspicious log entries..."
    grep "Failed password" /var/log/auth.log
}

# Function to harden SSH configuration
harden_ssh() {
    echo "Hardening SSH configuration..."
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
}

# Function to disable IPv6
disable_ipv6() {
    echo "Disabling IPv6..."
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
}

# Function to secure the bootloader
secure_bootloader() {
    echo "Securing the bootloader..."
    echo "Set a password for GRUB bootloader"
    grub-mkpasswd-pbkdf2
    echo "Add the generated password hash to /etc/grub.d/40_custom"
}

# Function to configure automatic updates
configure_automatic_updates() {
    echo "Configuring automatic updates..."
    apt-get install unattended-upgrades
    dpkg-reconfigure --priority=low unattended-upgrades
}

# Function to generate a summary report
generate_report() {
    echo "Generating summary report..."
    # Add your reporting logic here
}

# Main function to run all checks and hardening steps
main() {
    list_users_groups
    check_uid_0_users
    check_weak_passwords
    scan_world_writable
    check_ssh_permissions
    report_suid_sgid
    list_running_services
    check_unnecessary_services
    verify_firewall
    report_open_ports
    check_ip_forwarding
    check_ip_addresses
    check_security_updates
    check_suspicious_logs
    harden_ssh
    disable_ipv6
    secure_bootloader
    configure_automatic_updates
    generate_report
}

# Run the main function
main
