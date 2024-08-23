#!/bin/bash

# Function to display top 10 applications consuming the most CPU and memory
function top_apps() {
    echo "Top 10 Applications by CPU and Memory Usage:"
    ps aux --sort=-%cpu | head -n 11
    ps aux --sort=-%mem | head -n 11
}

# Function to monitor network
function network_monitor() {
    echo "Network Monitoring:"
    echo "Concurrent Connections: $(netstat -an | grep ESTABLISHED | wc -l)"
    echo "Packet Drops: $(netstat -s | grep 'packet receive errors')"
    echo "MB In: $(ifconfig eth0 | grep 'RX bytes' | awk '{print $2}' | cut -d: -f2)"
    echo "MB Out: $(ifconfig eth0 | grep 'TX bytes' | awk '{print $6}' | cut -d: -f2)"
}

# Function to display disk usage
function disk_usage() {
    echo "Disk Usage:"
    df -h | awk '$5 > 80 {print $0}'
}

# Function to show system load
function system_load() {
    echo "System Load:"
    uptime
    echo "CPU Usage Breakdown:"
    mpstat
}

# Function to display memory usage
function memory_usage() {
    echo "Memory Usage:"
    free -h
    echo "Swap Memory Usage:"
    swapon --show
}

# Function to monitor processes
function process_monitor() {
    echo "Process Monitoring:"
    echo "Active Processes: $(ps aux | wc -l)"
    echo "Top 5 Processes by CPU and Memory Usage:"
    ps aux --sort=-%cpu | head -n 6
    ps aux --sort=-%mem | head -n 6
}

# Function to monitor essential services
function service_monitor() {
    echo "Service Monitoring:"
    for service in sshd nginx apache2 iptables; do
        systemctl is-active --quiet $service && echo "$service is running" || echo "$service is not running"
    done
}

# Main script logic to handle command-line switches
case "$1" in
    -cpu)
        top_apps
        ;;
    -network)
        network_monitor
        ;;
    -disk)
        disk_usage
        ;;
    -load)
        system_load
        ;;
    -memory)
        memory_usage
        ;;
    -process)
        process_monitor
        ;;
    -service)
        service_monitor
        ;;
    *)
        echo "Usage: $0 {-cpu|-network|-disk|-load|-memory|-process|-service}"
        ;;
esac
