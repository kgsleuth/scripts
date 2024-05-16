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


log() {
    # Log messages with different severity levels and colors
    # Parameters:
    #   $1 - Severity level (info, warn, error, debug, trace)
    #   $2 - Message to log
    # Logs messages to the terminal with color formatting
    
    local level=""
    local message=""
    local color_level=""
    local color_message=""
    local color_time=""
    local syslog_severity=""

    local pid=$$

    case $1 in
        -i|--info)
            level="[INFO]"
            message="${@:2}"
            color_level="\033[0;32m"
            color_message="\033[0;94m"
            color_time="\033[0;33m"
            syslog_severity="info"
            ;;
        -w|--warn)
            level="[WARN]"
            message="${@:2}"
            color_level="\033[0;33m"
            color_message="\033[0;96m"
            color_time="\033[0;33m"
            syslog_severity="warning"
            ;;
        -e|--error)
            level="[ERROR]"
            message="${@:2}"
            color_level="\033[0;31m"
            color_message="\033[0;96m"
            color_time="\033[0;33m"
            syslog_severity="err"
            ;;
        -d|--debug)
            level="[DEBUG]"
            message="${@:2}"
            color_level="\033[0;36m"
            color_message="\033[0;96m"
            color_time="\033[0;33m"
            syslog_severity="debug"
            ;;
        -t|--trace)
            level="[TRACE]"
            message="${@:2}"
            color_level="\033[0;37m"
            color_message="\033[0;96m"
            color_time="\033[0;33m"
            syslog_severity="debug"
            ;;
        *)
            level="[UNKNOWN]"
            message="$@"
            color_level="\033[0m"
            color_message="\033[0;96m"
            color_time="\033[0;33m"
            syslog_severity="notice"
            ;;
    esac

    # Log to both the terminal and the specified log file with color formatting
    echo -e "$color_time$(date +'%Y-%m-%d %H:%M:%S') $color_level$level\033[0m - $color_message$message\033[0m"

    # Additionally, log to syslog with the specified severity level, including the level text
    logger -p "user.$syslog_severity" -t "$0" [$$] "$level $message"
}


upm() {
    # Manage package updates, clean-ups, and installations on Linux systems
    # Detects the system's package manager and performs specified actions
    # based on the options provided (update, clean, install, remove)

    usage() {
        echo "Usage: upm [options]"
        echo "This script must be run as root to manage packages on Linux systems."
        echo ""
        echo "Options:"
        echo "  -u, --update                    Updates the system's package lists and installs available updates."
        echo "  -c, --clean                     Cleans up the package manager's cache and removes orphaned dependencies."
        echo "  -p, --packages <package_names>  Installs specified packages. Multiple packages can be specified separated by spaces."
        echo "  -r, --remove   <package_names>  Removes specified packages. Multiple packages can be specified separated by spaces."
        echo "  -h, --help                      Displays this help information and exits."
        echo ""
        echo "Examples:"
        echo "  upm --update                    Update the system's package list and install updates."
        echo "  upm --clean                     Clean up unnecessary packages and cache."
        echo "  upm --packages nano vim         Install 'nano' and 'vim' packages."
    }


    detect_pkg_manager() {
        # Detect the available package manager on the system
        # Returns the package manager command if found, otherwise logs a warning
        
        local pkg_manager=""

        if command -v apt > /dev/null 2>&1; then
            pkg_manager="apt"
        elif command -v apt-get > /dev/null 2>&1; then
            pkg_manager="apt-get"
        elif command -v dnf > /dev/null 2>&1; then
            pkg_manager="dnf"
        elif command -v microdnf > /dev/null 2>&1; then
            pkg_manager="microdnf"
        elif command -v yum > /dev/null 2>&1; then
            pkg_manager="yum"
        else
            log --warn "No known package manager found."
            return 1
        fi

        echo "$pkg_manager"  
    }


    update_host() {
        # Updates the system's package list and installs updates.
        # Logs the start and end of the update process, capturing output of `dnf update` command.
        # If update is successful, logs success message; if it fails, logs error output and returns 1.
        
        case $PKG_MANAGER in
            apt|apt-get)
                $PKG_MANAGER update && $PKG_MANAGER upgrade -y
                ;;
            dnf|microdnf|yum)
                $PKG_MANAGER update -y
                ;;
            *)
                log --warn "Unsupported package manager for updating."
                return 1
                ;;
        esac
    }


    install_package() {
        # Installs provided dependencies using the system's package manager.
        # Logs installation attempts for each package and installation status.
        # Allows dynamic adjustment of required dependencies based on different contexts.
        
        if [ $# -eq 0 ]; then
            return 1
        fi
            
        for package_name in "$@"; do
            log --info "Installing ${package_name} using ${PKG_MANAGER} package manager."
            case $PKG_MANAGER in
                apt|apt-get|dnf|microdnf|yum)
                    $PKG_MANAGER install $package_name -y > /dev/null 2>&1
                    ;;
                *)
                    log --warn "Unsupported package manager for installing packages."
                    return 1
                    ;;
            esac        
            
            if [ $? -ne 0 ]; then
                log --warn "Failed to install $package_name."
            else
                log --info "\t$package_name installed successfully."
            fi
        done
    }


    remove_package() {
        # Removes specified packages using the detected package manager.
        # Parameters:
        #   $@ - List of package names to remove.
        # Logs removal status for each package.
        
        local pkg_manager=$1
        local package_name=$2

        log --info "Removing $package_name using $PKG_MANAGER..."
        for package_name in "$@"; do
            case $PKG_MANAGER in
                apt|apt-get|dnf|microdnf|yum)
                    $PKG_MANAGER remove $package_name -y
                    ;;
                *)
                    log --warn "Unsupported package manager for removing packages."
                    return 1
                    ;;
            esac
        done
    }


    clean_pkg_manager_cache() {
        # Cleans the cache of the specified package manager.
        # Supports apt, apt-get, dnf, microdnf, and yum.
         
        case $PKG_MANAGER in
            apt|apt-get)
                $PKG_MANAGER clean
                ;;
            dnf|microdnf|yum)
                $PKG_MANAGER clean all
                ;;
            *)
                return 1
                ;;
        esac
    }


    remove_orphaned_package() {
        # Removes orphaned dependencies for the specified package manager.
        # Supports apt, apt-get, dnf, and microdnf. Logs a warning for yum.
   
        case $PKG_MANAGER in
            apt)
                apt autoremove -y
                ;;
            apt-get)
                apt-get autoremove -y
                ;;
            dnf|microdnf)
                $PKG_MANAGER autoremove -y
                ;;
            yum)
                log --warn "Yum does not have a built-in equivalent to autoremove."
                ;;
            *)
                log --warn "Unsupported package manager for removing orphaned dependencies."
                return 1
                ;;
        esac
    }


    PKG_MANAGER=$(detect_pkg_manager)


    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--update)
                log --info "Starting update process for host and base system files."
                log --info "Updating $PKG_MANAGER and installed packages..."                
                update_host > /dev/null 2>&1
                ;;
            -c|--clean)
                log --info "Cleaning the cache for ${PKG_MANAGER}..."
                clean_pkg_manager_cache > /dev/null 2>&1
                remove_orphaned_package > /dev/null 2>&1
                ;;
            -i|--install)
                shift
                packages=("$@")
                log --info "Installing packages: ${packages[@]}"
                install_package "${packages[@]}" > /dev/null 2>&1
                break
                ;;
            -r|--remove)
                shift
                packages=("$@")
                log --info "Installing packages: ${packages[@]}"
                remove_c "${packages[@]}" > /dev/null 2>&1
                break
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log --info "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done
}


configure_firewall() {
    # Configure the firewall to allow specific traffic.
    # Enables and starts firewalld service, sets default target to DROP for all zones,
    # and adds specified ports and protocols to the firewall rules.

    drop_all_inbound_traffic() {
        # Set default target to DROP for all firewall zones.
        # Iterates over each zone and applies the DROP policy.
        
        zones=$(firewall-cmd --get-zones)

        for zone in $zones; do
            firewall-cmd --permanent --zone="$zone" --set-target=DROP
            echo "Default target for $zone set to DROP."
        done
    }
    

    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --enable)
                shift
                systemctl enable firewalld > /dev/null 2>&1
                ;;
            --start)
                shift
                systemctl start firewalld > /dev/null 2>&1
                ;;
            --reload)
                shift
                firewall-cmd --reload > /dev/null 2>&1
                ;;
            --drop-all)
                shift
                drop_all_inbound_traffic > /dev/null 2>&1
                ;;
            --port)
                shift
                port="$1"
                # shift
                ;;
            --protocol)
                shift
                protocol="$1"
                # shift
                ;;
            *)
                log --info "Unknown option: $1"
                exit 1
                ;;
        esac
        shift
    done

    if [[ -n "$port" && -n "$protocol" ]]; then
        if firewall-cmd --query-port="$port/$protocol"  > /dev/null 2>&1; then
            log --info "Port $port/$protocol is already added to the firewall rules."
        else
            firewall-cmd --add-port="$port/$protocol" --permanent  > /dev/null 2>&1
            log --info "Port $port/$protocol has been added to the firewall rules."
        fi
    fi
}    


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
