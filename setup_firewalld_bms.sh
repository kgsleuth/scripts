#!/usr/bin/env bash

# Script: setup_firewalld_bms.sh
# Description: This script installs and updates firewalld on an Ubuntu server,
#              sets the default incoming policy to deny, allows traffic from a specified list of IP addresses
#              and IP ranges in CIDR notation, configures inbound rules for common Building Management System (BMS) ports,
#              and enables the firewall.
#
# Usage: Run this script as root to ensure it can make the necessary changes.
#        Example: ./setup_firewalld_bms.sh
#
# IP Addresses: Modify the ALLOWED_IPS_192 and ALLOWED_IPS_220 arrays to include individual IP addresses that should be allowed.
# BMS Ports: Modify the BMS_PORTS array to include the necessary BMS ports and protocols.

# Update package lists and install firewalld
echo "Updating package lists and installing firewalld..."
apt update
apt install -y firewalld

# Start and enable firewalld
echo "Starting and enabling firewalld..."
systemctl start firewalld
systemctl enable firewalld

# Set the lifecycle environment variable (PROD or DEV)
LIFECYCLE="PROD"

# Set default policies based on lifecycle
echo "Setting default policies based on lifecycle ($LIFECYCLE)..."
if [ "$LIFECYCLE" == "PROD" ]; then
    firewall-cmd --set-default-zone=block
else
    firewall-cmd --set-default-zone=public
fi

# Allow all traffic on interface ens160
echo "Allowing all traffic on interface ens160..."
firewall-cmd --zone=trusted --add-interface=ens160 --permanent

# List of allowed IPs for ens192
ALLOWED_IPS_192=(
    "192.168.130.10"
    "192.168.130.20"
    # Add more IPs as needed
)

# List of allowed IPs for ens220
ALLOWED_IPS_220=(
    "192.168.138.10"
    "192.168.138.20"
    # Add more IPs as needed
)

# Configure ens192 based on lifecycle
echo "Configuring rules for ens192 based on lifecycle ($LIFECYCLE)..."
for ip in "${ALLOWED_IPS_192[@]}"; do
    if [ "$LIFECYCLE" == "PROD" ]; then
        firewall-cmd --zone=trusted --add-source=$ip --permanent
    else
        firewall-cmd --zone=drop --add-source=$ip --permanent
    fi
done

# Configure ens220 based on lifecycle
echo "Configuring rules for ens220 based on lifecycle ($LIFECYCLE)..."
for ip in "${ALLOWED_IPS_220[@]}"; do
    if [ "$LIFECYCLE" == "PROD" ]; then
        firewall-cmd --zone=trusted --add-source=$ip --permanent
    else
        firewall-cmd --zone=drop --add-source=$ip --permanent
    fi
done

# Reload firewalld to apply changes
echo "Reloading firewalld to apply changes..."
firewall-cmd --reload

# Print firewalld status
echo "Printing firewalld status..."
firewall-cmd --list-all-zones
