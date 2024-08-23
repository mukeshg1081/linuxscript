#!/bin/bash

# Function to list all users and groups
user_group_audit() {
    echo "User and Group Audit:"
    echo "All Users:"
    cut -d: -f1 /etc/passwd
    echo "All Groups:"
    cut -d: -f1 /etc/group
    echo "Users with UID 0:"
    awk -F: '($3 == "0") {print}' /etc/passwd
    echo "Users without passwords or with weak passwords:"
    awk -F: '($2 == "" || length($2) < 8) {print $1}' /etc/shadow
}

# Function to check file and directory permissions
file_permission_audit() {
    echo "File and Directory Permissions Audit:"
    echo "World-writable files and directories:"
    find / -xdev -type d -perm -0002 -print
    find / -xdev -type f -perm -0002 -print
    echo ".ssh directories with insecure permissions:"
    find /home -type d -name ".ssh" -exec ls -ld {} \;
    echo "Files with SUID or SGID bits set:"
    find / -perm /6000 -type f -exec ls -ld {} \;
}

# Function to list running services and check for unauthorized services
service_audit() {
    echo "Service Audit:"
    echo "Running services:"
    systemctl list-units --type=service --state=running
    echo "Critical services status:"
    for service in sshd iptables; do
        systemctl is-active --quiet $service && echo "$service is running" || echo "$service is not running"
    done
    echo "Services listening on non-standard or insecure ports:"
    netstat -tuln | grep -v ':22\|:80\|:443'
}

# Function to verify firewall and network security
firewall_network_audit() {
    echo "Firewall and Network Security Audit:"
    echo "Firewall status:"
    ufw status
    echo "Open ports and associated services:"
    netstat -tuln
    echo "IP forwarding status:"
    sysctl net.ipv4.ip_forward
}

# Function to check IP and network configurations
ip_network_config() {
    echo "IP and Network Configuration Checks:"
    echo "Public vs. Private IPs:"
    ip -o -4 addr list | awk '{print $4}' | while read -r ip; do
        if [[ $ip =~ ^10\.|^172\.16\.|^192\.168\. ]]; then
            echo "Private IP: $ip"
        else
            echo "Public IP: $ip"
        fi
    done
}

# Function to check for security updates and patches
security_updates() {
    echo "Security Updates and Patching:"
    apt-get update
    apt-get upgrade -s | grep -i security
}

# Function to monitor logs for suspicious activity
log_monitoring() {
    echo "Log Monitoring:"
    echo "Recent suspicious log entries:"
    grep "Failed password" /var/log/auth.log | tail -n 10
}

# Function to implement server hardening steps
server_hardening() {
    echo "Server Hardening Steps:"
    echo "Implementing SSH key-based authentication and disabling password-based login for root:"
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
    echo "Disabling IPv6:"
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p
    echo "Securing the bootloader:"
    grub-mkpasswd-pbkdf2
    echo "Implementing recommended iptables rules:"
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables-save > /etc/iptables/rules.v4
    echo "Configuring automatic updates:"
    apt-get install unattended-upgrades
    dpkg-reconfigure --priority=low unattended-upgrades
}

# Function to generate a summary report
generate_report() {
    echo "Generating Summary Report:"
    user_group_audit
    file_permission_audit
    service_audit
    firewall_network_audit
    ip_network_config
    security_updates
    log_monitoring
    server_hardening
}

# Main function to run all audits and hardening steps
main() {
    generate_report
}

# Run the main function
main
