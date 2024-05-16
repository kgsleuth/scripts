#!/bin/bash

# Script: setup_firewalld_bms.sh
# Description: This script installs and starts firewalld on an Oracle Linux server,
#              sets the default incoming policy to deny, allows traffic from a specified list of IP addresses
#              and IP ranges in CIDR notation, configures inbound rules for common Building Management System (BMS) ports,
#              and reloads the firewall configuration.
# 
# Usage: Run this script as root to ensure it can make the necessary changes.
#        Example: ./setup_firewalld_bms.sh
#
# IP Addresses: Modify the IP_LIST array to include individual IP addresses that should be allowed.
# IP Ranges: Modify the CIDR_LIST array to include the IP ranges (in CIDR notation) that should be allowed.
# BMS Ports: Modify the BMS_PORTS array to include the necessary BMS ports and protocols.
#
# Version: 1.0

## Imports
# Download common.sh
download_file() {
  # This function takes two arguments: the URL to download and the output file path.
  # It will attempt to download the file up to 5 times, waiting 5 seconds between
  # each attempt. If the download fails after 5 attempts, the function returns 1.

    local url=$1
    local output=$2
    local retries=5
    local wait=5

    for ((i=1; i<=retries; i++)); do
        if curl -o "$output" "$url"; then
            echo "Download succeeded on attempt $i."
            return 0
        else
            echo "Download failed on attempt $i. Retrying in $wait seconds..."
            sleep $wait
        fi
    done

    echo "Download failed after $retries attempts."
    return 1
}

# Create directory if it doesn't exist
mkdir -p lib

# Download common.sh with retries
if ! download_file "<url-to-common.sh>" "lib/common.sh"; then
    echo "Failed to download common.sh. Exiting."
    exit 1
fi

# Source the common.sh file
source lib/common.sh

main() {
    # Main function to orchestrate the firewall setup.
    # Updates the host, installs required packages, configures firewalld,
    # and sets firewall rules for specified IP addresses and BMS ports.
     
    packages=( firewalld )
    ip_list=("192.168.1.10" "10.0.0.5")               # List of individual IP addresses
    cidr_list=("192.168.1.0/24" "10.0.0.0/24")        # List of IP ranges in CIDR notation
    
    
    log --info "Updating the host and installing required packages"
    upm --update  
    log --info "Install necessary dependencies..."
    upm --install "${packages[@]}"  
    log --info "Freeing up space and removing outdated packages by clearing the package manager cache"
    upm --clean
    
    upm --packages firewalld
    systemctl start firewalld
    systemctl enable firewalld
    
    log --info "Enabling and starting firewall service"
    configure_firewall  --enable
    configure_firewall  --start
    
    log --info "Setting firewall to drop all inbound connections."
    configure_firewall  --drop-all 
    
    log --info "Configuring BMS ports."
    # BMS Ports: "47808/udp" "502/tcp" "3671/udp" "1628/udp" "1629/udp" "1911/tcp" "4911/tcp"
    configure_firewall  --port 47808  --protocol udp  
    configure_firewall  --port 3671   --protocol udp  
    configure_firewall  --port 1628   --protocol udp  
    configure_firewall  --port 1629   --protocol udp  
    configure_firewall  --port 502    --protocol tcp  
    configure_firewall  --port 1911   --protocol tcp  
    configure_firewall  --port 4911   --protocol tcp  

    # SSH/PRA Ports: "22/tcp"
    configure_firewall --port 22 --protocol tcp
    
    # Allow traffic from specified IP addresses
    for ip in "${ip_list[@]}"; do
      firewall-cmd --permanent --zone=trusted --add-source=$ip
    done
    
    # Allow traffic from specified IP ranges in CIDR notation
    for cidr in "${cidr_list[@]}"; do
      firewall-cmd --permanent --zone=trusted --add-source=$cidr
    done
    
    log --info "Loading new configurations"
    configure_firewall  --reload
    
    log --info "Restart necessary services to apply the new configurations."
    systemctl restart firewalld

}

main
