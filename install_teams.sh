#!/bin/bash

# Add the Microsoft GPG Key
echo "Adding Microsoft GPG Key..."
curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

# Add Microsoft Teams Repository
echo "Adding Microsoft Teams repository..."
sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/ms-teams stable main" > /etc/apt/sources.list.d/teams.list'

# Update Package Lists
echo "Updating package lists..."
sudo apt update

# Install Microsoft Teams
echo "Installing Microsoft Teams..."
sudo apt install teams -y

echo "Microsoft Teams installation completed."
