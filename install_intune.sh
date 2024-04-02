#!/bin/bash

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*"
}

# Ensure the script is run as root
if [ "$(id -u)" != "0" ]; then
   log "This script must be run as root" 1>&2
   exit 1
fi

# Determine Ubuntu version
UBUNTU_VERSION=$(lsb_release -rs)
CODENAME=$(lsb_release -sc)

# Download and add the Microsoft package signing key
curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg
sudo install -o root -g root -m 644 microsoft.gpg /usr/share/keyrings/

# Add the package repository using interpolation for the Ubuntu version and codename
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/ubuntu/${UBUNTU_VERSION}/prod ${CODENAME} main" | sudo tee /etc/apt/sources.list.d/microsoft-ubuntu-${CODENAME}-prod.list > /dev/null

# Remove the temporary GPG key file
sudo rm microsoft.gpg

# Update the package lists
sudo apt update

# Install the Microsoft Intune app
sudo apt install -y intune-portal

if [ $? -eq 0 ]; then
    log "Microsoft Intune app installed successfully."
else
    log "Failed to install the Microsoft Intune app."
    exit 1
fi
