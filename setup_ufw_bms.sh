#!/usr/bin/env bash

# Script: setup_ufw_bms.sh
# Description: This script installs and updates UFW (Uncomplicated Firewall) on an Ubuntu server,
#              sets the default incoming policy to deny, allows traffic from a specified list of IP addresses
#              and IP ranges in CIDR notation, configures inbound rules for common Building Management System (BMS) ports,
#              and enables the firewall.
#
# Usage: Run this script as root to ensure it can make the necessary changes.
#        Example: ./setup_ufw_bms.sh
#
# IP Addresses: Modify the ALLOWED_IPS_192 and ALLOWED_IPS_220 arrays to include individual IP addresses that should be allowed.
# BMS Ports: Modify the BMS_PORTS array to include the necessary BMS ports and protocols.

# Update package lists and install UFW
echo "Updating package lists and installing UFW..."
apt update
apt install -y ufw

# Set the lifecycle environment variable (PROD or DEV)
LIFECYCLE="PROD"

# Enable UFW
echo "Enabling UFW..."
ufw --force enable

# Set default policies based on lifecycle
echo "Setting default policies based on lifecycle ($LIFECYCLE)..."
if [ "$LIFECYCLE" == "PROD" ]; then
    ufw default deny incoming
    ufw default deny outgoing
else
    ufw default allow incoming
    ufw default allow outgoing
fi

# Allow all traffic on interface ens160
echo "Allowing all traffic on interface ens160..."
ufw allow in on ens160
ufw allow out on ens160

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
        ufw allow in on ens192 from $ip
        ufw allow out on ens192 to $ip
    else
        ufw deny in on ens192 from $ip
        ufw deny out on ens192 to $ip
    fi
done

# Configure ens220 based on lifecycle
echo "Configuring rules for ens220 based on lifecycle ($LIFECYCLE)..."
for ip in "${ALLOWED_IPS_220[@]}"; do
    if [ "$LIFECYCLE" == "PROD" ]; then
        ufw allow in on ens220 from $ip
        ufw allow out on ens220 to $ip
    else
        ufw deny in on ens220 from $ip
        ufw deny out on ens220 to $ip
    fi
done

# Enable UFW logging
echo "Enabling UFW logging..."
ufw logging on

# Reload UFW to apply changes
echo "Reloading UFW to apply changes..."
ufw reload

# Print UFW status
echo "Printing UFW status..."
ufw status verbose
