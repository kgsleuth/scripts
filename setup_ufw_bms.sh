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
# IP Addresses: Modify the IP_LIST array to include individual IP addresses that should be allowed.
# IP Ranges: Modify the CIDR_LIST array to include the IP ranges (in CIDR notation) that should be allowed.
# BMS Ports: Modify the BMS_PORTS array to include the necessary BMS ports and protocols.

# TODO :: Integrate functions and additional functionality

# Define variables
IP_LIST=("192.168.1.10" "10.0.0.5")               # List of individual IP addresses
CIDR_LIST=("192.168.1.0/24" "10.0.0.0/24")        # List of IP ranges in CIDR notation
BMS_PORTS=("47808/udp" "502/tcp" "3671/udp" "1628/udp" "1629/udp" "1911/tcp" "4911/tcp")

# Update package lists and install UFW
apt update
apt install -y ufw

# Set default policies
ufw default deny incoming
ufw default allow outgoing

# Allow traffic from specified IP addresses if the list is not empty
if [ ${#IP_LIST[@]} -gt 0 ]; then
    for IP in "${IP_LIST[@]}"; do
        ufw allow from $IP
    done
fi

# Allow traffic from specified IP ranges in CIDR notation if the list is not empty
if [ ${#CIDR_LIST[@]} -gt 0 ]; then
    for CIDR in "${CIDR_LIST[@]}"; do
        ufw allow from $CIDR
    done
fi

# Allow inbound BMS ports
for PORT in "${BMS_PORTS[@]}"; do
    ufw allow $PORT
done

# Enable UFW
ufw enable

# Check UFW status
ufw status verbose
