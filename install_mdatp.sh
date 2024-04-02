#!/bin/bash

# Define function to log messages
log() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*"
}

# Check for root privileges
if [ "$(id -u)" != "0" ]; then
   log "This script must be run as root" 1>&2
   exit 1
fi

# Add Microsoft's package signing key to your list of trusted keys
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

# Automatically determine Ubuntu version and add the package repository
UBUNTU_VERSION=$(lsb_release -rs)
REPO_URL="https://packages.microsoft.com/config/ubuntu/$UBUNTU_VERSION/prod.list"

wget -qO - $REPO_URL | sudo tee /etc/apt/sources.list.d/microsoft-prod.list > /dev/null

if [ $? -ne 0 ]; then
    log "Failed to add repository for Ubuntu version $UBUNTU_VERSION"
    exit 1
else
    log "Repository for Ubuntu version $UBUNTU_VERSION added successfully"
fi

# Update the package list
sudo apt-get update

# Install Microsoft Defender for Endpoint
sudo apt-get install -y mdatp

# Start the daemon
sudo systemctl start mdatp
sudo systemctl enable mdatp

log "Microsoft Defender for Endpoint installation and setup complete."
