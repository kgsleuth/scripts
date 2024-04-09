#!/usr/bin/env bash
# Script Name: bootstrap-syslog-enhanced.sh
# Description: This Bash script automates the configuration of various aspects
#              of a Linux system, focusing on logging, security, and service
#              management. It sets up log rotation, rsyslog, SELinux, firewall,
#              and other configurations to ensure efficient and secure operation
#              of the system.

# Corporate Use License:
#   This script is provided "as is", without warranty of any kind, express or implied, 
#   and is intended for use by Stream Datacenters employees or systems only. Unauthorized 
#   use, distribution, or modification outside of Stream Datacenters is strictly prohibited. 

# This script performs several administrative tasks to secure and manage logging on a Linux server:
#   - Ensures the script is run with root privileges for necessary permissions
#   - Updates the system and installs Python3 for script dependencies
#   - Configures SELinux to allow rsyslog traffic on specific ports
#   - Adjusts the firewall settings to permit rsyslog traffic
#   - Installs rsyslog and rsyslog-gnutls 
#   - Sets up a custom logrotate configuration for efficient log management
#   - Configures Azure Sentinel connector if required ports are not listening


# Define global variables for the logrotate configuration file and the log file
# Path to the log file
LOG_FILE="bootstrap.log"

## Variables for certificate subject fields
# Certificate subject fields for generating SSL certificatesCOUNTRY="US"
STATE="California"
CITY="San Francisco"
ORGANIZATION="Azure" ## west-us-3
COMMON_NAME="stream-dc.com"

## Default paths for self-signed certificates
CA_CERT="${CA_CERT:-/etc/ssl/certs/rsyslog-ca-cert.pem}"
SERVER_CERT="${SERVER_CERT:-/etc/ssl/certs/rsyslog-server-cert.pem}"
SERVER_KEY="${SERVER_KEY:-/etc/ssl/private/rsyslog-server-key.pem}"

## Log rotation configuration content
LOGROTATE_CONF_DIR="/etc/logrotate.d"
LOGROTATE_CONF_PATH="$LOGROTATE_CONF_DIR/all_logs"
LOGROTATE_CONF=$(cat <<'EOF'
## Log rotation configuration content

# This logrotate configuration defines rotation settings for all logs on the
# host. It rotates logs located in /var/log and its subdirectories, keeping
# three rotated copies and rotating logs daily. If a log file exceeds 100
# megabytes or the total log size surpasses 20 gigabytes, it triggers rotation.
# Rotated logs are compressed, and compression is delayed until the next
# rotation. The configuration handles missing and empty logs gracefully, sets
# ownership and permissions for new log files, and runs postrotate scripts for
# additional actions such as rotating syslog logs and deleting older logs if the
# total size exceeds the limit or if logs are older than three days.

# Rotate all logs in /var/log and its subdirectories
/var/log/* /var/log/*/* {
    rotate 3
    daily
    size 100M
    total size 20G
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    # postrotate
    #     /usr/sbin/logrotate /etc/logrotate.conf
    #     total_size=$(du -sh /var/log | cut -f1)
    #     if [ "$(echo "$total_size > 20G" | bc)" -eq 1 ]; then
    #         echo "Total log size exceeds 20 gigabytes. Deleting older logs..."
    #         find /var/log -type f -mtime +3 -exec rm {} \;
    #     fi
    # endscript
}
EOF
)


# Rsyslog configuration paths
RSYSLOG_CONF_DIR="/etc/rsyslog.d"
RSYSLOG_CONF_PATH="$RSYSLOG_CONF_DIR/50-rsyslog-normal.conf"
RSYSLOG_TLS_CONF_PATH="$RSYSLOG_CONF_DIR/99-rsyslog-tls.conf"


# Define normal syslog configuration for port 514 (UDP and TCP)
RSYSLOG_CONF=$(cat <<EOF
# Config loads UDP/TCP modules once to avoid duplicates. It sets inputs for
# UDP/TCP (incl. TLS) on designated ports. Dynamic template for log filenames
# uses hostname/program. A unified ruleset processes all messages, streamlining
# syslog handling, improving management, security, and log organization.

## Load modules for UDP/TCP syslog. Ensures no duplicate module loading.
# module(load="imudp") # For UDP
# module(load="imtcp") # For TCP & TLS

## Define UDP input on port 514 for syslog messages.
input(type="imudp" port="514" address="0.0.0.0" ruleset="remoteLogs")

# Define TCP input on port 514 for non-TLS syslog.
input(type="imtcp" port="514" address="0.0.0.0" ruleset="remoteLogs")


# Define TCP input on port 6514 for TLS-encrypted syslog.
input(type="imtcp" port="6514" address="0.0.0.0" ruleset="remoteLogs")


# Template for dynamic log file naming based on hostname and program.
template(name="RemoteLogFileName" type="string" 
         string="/var/log/%HOSTNAME%/%PROGRAMNAME%.log")

# Ruleset for processing all syslog messages.
# Applies unified processing for both standard and encrypted logs.
ruleset(name="remoteLogs") {
    action(type="omfile" DynaFile="RemoteLogFileName")
}

# This configuration streamlines syslog processing, ensuring efficient
# log management and facilitating secure, organized storage of log data.

# # Set the logging level to "warning" to filter out lower severity messages
# # such as informational and debug messages, leaving only warning and error messages.
# $LogLevel warning

EOF
)


# Secure syslog  configuration content
RSYSLOG_TLS_CONF=$(cat <<'EOF'
# Load necessary modules for TCP syslog messages and TCP syslog messages with TLS
# encryption. Define input for TCP syslog messages with TLS encryption on port
# 6514. Specify a template for log file names, indicating the directory path and
# placeholders for hostname and program name. Establish a ruleset named
# "remoteLogs" for processing incoming syslog messages, directing the system to
# log messages to a file specified by the defined template.

# Define TLS settings for syslog
$DefaultNetstreamDriver gtls
$DefaultNetstreamDriverCAFile /etc/ssl/certs/rsyslog-ca-cert.pem
$DefaultNetstreamDriverCertFile /etc/ssl/certs/rsyslog-server-cert.pem
$DefaultNetstreamDriverKeyFile /etc/ssl/private/rsyslog-server-key.pem
# $ActionSendStreamDriverAuthMode x509/name
# $ActionSendStreamDriverPermittedPeer *.stream-dc.com

EOF
)


usage() {
    # Checks if the script is run as root and exits with an error if not.
    # This ensures the script has necessary permissions for system configuration modification.
    # If not run as root, it prints an error message to standard error and exits with a status code of 1.
    

    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root" 1>&2
        exit 1
    fi
}


log() {
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
    # This function serves as a utility for managing package updates, clean-ups,
    # and installations on Linux systems. It detects the system's package manager,
    # and based on the options provided, it can update the package lists, clean up
    # unnecessary packages, or install specified packages. The function requires
    # root privileges to execute package management commands.

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
        # Detects the available package manager on the system.

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
        # Removes a package using the specified package manager.

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


install_oms_agent() {
    # Attempts to set up Azure Sentinel connector.
    # Checks if syslog ports (514 or 6514) are already in use.
    # If not, downloads and executes Azure Sentinel connector setup script.
    # Logs outcome of checks and actions for transparency in setup process.
    
    local workspaceID=$1
    local primaryKey=$2

    if ss -tulpn | grep -E ":6?514\b"; then
        log --info "Port 514 or 6514 is open and listening."
    else
        log --info "Port 514 or 6514 is not open."
        log --info "Setting up Azure Sentinel connector..."
        wget -O cef_installer.py "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/DataConnectors/CEF/cef_installer.py" >> "$LOG_FILE" 2>&1
        python3 cef_installer.py "$workspaceID" "$primaryKey" >> "$LOG_FILE" 2>&1
    fi
}


generate_tls_certificates() {
    # Ensures the presence of a server's SSL certificate and key, generating new ones if absent.
    # This function is critical for initializing secure communication channels for services
    # requiring SSL/TLS, providing a default security posture.
    CA_CERT="${CA_CERT:-/etc/ssl/certs/rsyslog-ca-cert.pem}"
    SERVER_CERT="${SERVER_CERT:-/etc/ssl/certs/rsyslog-server-cert.pem}"
    SERVER_KEY="${SERVER_KEY:-/etc/ssl/private/rsyslog-server-key.pem}"

    update_permission_on_keys() {
        # Updates the permission and the owner on the server key
        log --info "Updating permission and owner of $SERVER_KEY & $SERVER_KEY"
        if [ -n "$SERVER_KEY" ] && [ -f "$SERVER_KEY" ]; then
            log --info "Adjusting permissions for the private key at $SERVER_KEY."
            chown root:root "$SERVER_KEY"
            chmod 600 "$SERVER_KEY"
        else
            log --warn "SERVER_KEY is not set or points to a non-existent file $SERVER_KEY. Skipping permission adjustment."
        fi
    }
    generate_self_signed_cert() {
        # Generates a self-signed SSL certificate and corresponding RSA private key.
        # This internal utility is targeted towards development or internal network applications,
        # where the certificate's issuer authenticity is less critical, yet secure communication
        # is still required.

        # Prepares the necessary directories for storing the CA certificate and server key.
        mkdir -p "$(dirname "$CA_CERT")" "$(dirname "$SERVER_KEY")"

        # If the CA certificate does not exist, it generates a new one valid for 365 days.
        if [ ! -f "$CA_CERT" ]; then
            openssl req -new -x509 -days 365 -nodes \
                -out "$CA_CERT" -keyout "$SERVER_KEY" \
                -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/CN=$COMMON_NAME"
            log --info "Generated self-signed CA certificate."
            log --info "Created CA certificate: $CA_CERT"
        else
            log --info "Using existing CA certificate: $CA_CERT"
        fi

        # If the server certificate and RSA private key do not exist, it generates a new one
        if [ ! -f "$SERVER_CERT" ] || [ ! -f "$SERVER_KEY" ]; then
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "$SERVER_KEY" -out "$SERVER_CERT" \
                -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/CN=$COMMON_NAME"
            log --info "Generated self-signed server certificate and key."
            log --info "Created server certificate: $SERVER_CERT"
            log --info "Created RSA private key: $SERVER_KEY"
        else
            log --info "Using existing server certificate: $SERVER_CERT"
            log --info "Using existing RSA private key: $SERVER_KEY"
        fi
    }

    # Verifies the existence of the server certificate and key, generating new ones if necessary.
    if [ ! -f "$SERVER_CERT" ] || [ ! -f "$SERVER_KEY" ]; then
        log --info "Certificate or key not found. Generating self-signed certificate."
        generate_self_signed_cert >/dev/null 2>&1
    else
        log --info "Using provided certificate and key."
        log --info "Using existing CA certificate: $CA_CERT"
        log --info "Using existing server certificate: $SERVER_CERT"
        log --info "Using existing RSA private key: $SERVER_KEY"
    fi

    update_permission_on_keys
}


generate_self_signed_cert_if_none_provided() {
    # Checks for existence of SSL certificate and key.
    # Generates a new self-signed certificate and key pair if either is not found.
    # Ensures SSL/TLS services have necessary files to start securely.

    if [ ! -f "$SERVER_CERT" ] || [ ! -f "$SERVER_KEY" ]; then
        log --info "Certificate or key not found. Generating self-signed certificate."
        generate_self_signed_cert >/dev/null 2>&1
    else
        log --info "Using provided certificate and key."
        log --info "Using existing CA certificate: $CA_CERT"
        log --info "Using existing server certificate: $SERVER_CERT"
        log --info "Using existing RSA private key: $SERVER_KEY"
    fi
}


update_permission_on_keys() {
    # Updates the permission and the owner on the server key

    log --info "Updating permission and owner of $SERVER_KEY & $SERVER_KEY"
    if [ -n "$SERVER_KEY" ] && [ -f "$SERVER_KEY" ]; then
        log --info "Adjusting permissions for the private key at $SERVER_KEY."
        chown root:root "$SERVER_KEY"
        chmod 600 "$SERVER_KEY"
    else
        log --warn "SERVER_KEY is not set or points to a non-existent file $SERVER_KEY. Skipping permission adjustment."
    fi
}


configure_selinux() {
    # Configures SELinux for specified services to enhance security. Iterates
    # over services, checks SELinux installation, and applies custom SELinux
    # policies if applicable. Skips configuration if running inside Docker or
    # SELinux is not installed. Logs actions and SELinux status. Accepts
    # service names as positional parameters.

    usage() {
        echo "Usage: configure_selinux [options]"
        echo "Usage: "This script must be run as root.""
        echo "  -b, --bootstrap  Bootstrap option, does not take in arguments"
        echo "                   and will review all running services on the"
        echo "                   host, and create custom SELinux policies as"
        echo "                   needed."
        echo "  -s, --service    Followed by one or more services to create"
        echo "                   custom SELinux policies as needed."
        echo "  -h, --help       Display this help and exit."
        echo ""
        echo "Examples:"
        echo "  configure_selinux --bootstrap"
        echo "  configure_selinux --service firewalld rsyslog"
    }


    # Parse command-line arguments manually
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -b|--bootstrap)
                # Get running services for bootstrap option
                readarray -t services < <(systemctl list-units --type=service \
                    --state=running | grep -o -E "\w+.service" | sed -E "s/\..*//g")
                shift
                ;;
            -s|--service)
                shift
                services=("$@")
                break
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            --)
                shift
                break
                ;;
            *)
                log --info "Programming error"
                exit 3
                ;;
        esac
    done


    sed -E -i 's/SELINUX=(disabled|permissive)/SELINUX=enforcing/g' /etc/selinux/config


    create_selinux_policy_for_service() {
        # This function creates and applies a custom SELinux policy for a specified
        # service. It restarts the service to generate SELinux denials, which are
        # then used to create a custom policy module. 
        
        local service_name=$1

        if [[ -z "$service_name" ]]; then
            log --info "Usage: create_selinux_policy_for_service <service-name>"
            return 1
        fi

        systemctl restart "$service_name" 

        ausearch -m avc -ts recent  |\
            grep "$service_name"    |\
            audit2allow -M           \
            "custom_${service_name}_policy"
    
        if [ -f "custom_${service_name}_policy.pp" ]; then
            semodule -i "custom_${service_name}_policy.pp"  
        fi
    }  


    if [ -f "/.dockerenv" ]; then
        log --info "Running inside Docker, skipping SELinux configurations."
    else
        if command -v sestatus &>/dev/null; then
            log --info "SELinux is installed, proceeding with SELinux port configuration."
            log --info "Setting SELinux to permissive mode to collect denials:"
            setenforce 0
            log --info "Services to review: ${services[@]}"
            for service in "${services[@]}"; do
                log --info "Generating SELinux policy module for ${service}."
                log --info "Installing the custom SELinux ${service}_custom_policy.pp module."
                create_selinux_policy_for_service "$service"  > /dev/null 2>&1
                log --info "Custom SELinux policy for $service has been created and applied."
            done
            setenforce 1 
            log --info "Setting SELinux back to enforcing mode."
        else
            log --info "SELinux is not installed. Skipping SELinux configurations."
        fi
    fi
}


configure_firewall() {
    # Configures the system's firewall to allow rsyslog traffic, enabling the
    # receipt of remote logs. Checks if running inside a Docker container, skips
    # firewall configurations if true. If not running inside Docker, enables and
    # starts the firewalld service.

    if [ -f "/.dockerenv" ]; then
        log --info "Running inside Docker; skipping firewall configuration."
        return
    fi

    drop_all_inbound_traffic() {
        # Get a list of all zones
        zones=$(firewall-cmd --get-zones)

        # Iterate over each zone and set the default target to DROP
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


config_builder() {
    local config_path=$1
    local config_content=$2
    local config_name=$3

    log --info "Checking and updating ${config_name} configuration as necessary..."

    mkdir -p "$(dirname "$config_path")"

    if [ -f "$config_path" ]; then
        existing_content=$(cat "$config_path")

        yes | cp --force "$config_path" "${config_path}.bak" >/dev/null 2>&1

        log --info "Backup of existing ${config_name} configuration created at ${config_path}.bak"

        if [ "$config_content" = "$existing_content" ]; then
            log --info "${config_name} configuration already exists and is up to date: $config_path"
        else
            log --info "${config_name} configuration exists but is different. Updating: $config_path"
            echo "$config_content" > "$config_path"
        fi
    else
        log --info "Creating ${config_name} configuration at $config_path."
        echo "$config_content" > "$config_path"
    fi
}


set_cron_to_delete_old_logs() {
    # Define the cron job command to delete files in /var/log older than 3 days
    local CRON_JOB="0 */4 * * * /usr/bin/find /var/log -type f -mtime +3 -exec rm -f {} \;"

    # Check if the cron job exists in the current crontab
    if ! (crontab -l 2>/dev/null | grep -Fq "$CRON_JOB"); then
        # Add the cron job to the crontab if it does not exist
        (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    fi
}


main() {
    # Define local variables for the azure workspace and secret
    local azure_workspace=$1
    local secret_key=$2

    usage

    log --info "Script execution started."

    packages=( python3 policycoreutils-python-utils rsyslog rsyslog-gnutls )

    log --info "Updating the host and installing required packages"
    upm --update  
    log --info "Install necessary dependencies..."
    upm --install "${packages[@]}"  
    log --info "Freeing up space and removing outdated packages by clearing the package manager cache"
    upm --clean

    setenforce 0

    log --info "Generating a self-signed certificate for TLS if none is provided, ensuring secure communication for syslog over TLS"
    generate_tls_certificates

    [ ! -f "/.dockerenv" ] && log --info "Installing the Azure Monitor Agent" || log --info "Skipping OMS Install, in staging environment"
    [ ! -f "/.dockerenv" ] && install_oms_agent $azure_workspace $secret_key

    log --info "Configure syslog services for log rotation and secure reception."
    config_builder "$LOGROTATE_CONF_PATH"       "$LOGROTATE_CONF"   "Custom logrotate"
    config_builder "$RSYSLOG_CONF_PATH"         "$RSYSLOG_CONF"     "Normal log reception"
    config_builder "$RSYSLOG_TLS_CONF_PATH"     "$RSYSLOG_TLS_CONF" "Secure log reception"

    log --info "Enabling and starting firewall service"
    configure_firewall  --enable
    configure_firewall  --start

    log --info "Setting firewall to drop all inbound connections."
    configure_firewall  --drop-all 

    log --info "Configuring syslog reviecer ports."
    configure_firewall  --port 514  --protocol udp  
    configure_firewall  --port 514  --protocol tcp  
    configure_firewall  --port 6514 --protocol tcp  

    log --info "Loading new configurations"
    configure_firewall  --reload

    log --info "Restart necessary services to apply the new configurations."
    systemctl restart firewalld
    systemctl restart rsyslog

    log --info "Creating a CRON job to delete logs older than 3 days."
    set_cron_to_delete_old_logs

    log --info "Configuring security profiles for SELinux."
    configure_selinux --bootstrap
    
    log --info "Script execution completed."
}

# Initiates the script execution by calling the main function.
# Parse command line options
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -w|--workspace-id)
            shift
            azure_workspace="$1"
            ;;
        -s|--secret-key)
            shift
            secret_key="$1"
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
    shift
done


# This is the entry point of the script, and checks if both azure_workspace and secret_key variables are provided
[[ -n "$azure_workspace" && -n "$secret_key" ]] && main "$azure_workspace" "$secret_key" 
