log() {
    # Log messages with severity levels and colors.
    # Parameters: $1 - level (info, warn, error, debug, trace), $2 - message.
    # Logs messages to the terminal and syslog with color formatting.

    usage() {
        echo "Usage: log [option] message"
        echo "Options:"
        echo "  -i, --info    Info level message"
        echo "  -w, --warn    Warning level message"
        echo "  -e, --error   Error level message"
        echo "  -d, --debug   Debug level message"
        echo "  -t, --trace   Trace level message"
        echo "Example:"
        echo "  log -i 'This is an info message'"
        echo "  log --warn 'This is a warning'"
    }

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
            message="${*:2}"
            color_level="\033[0;32m"
            color_message="\033[0;94m"
            color_time="\033[0;33m"
            syslog_severity="info"
            ;;
        -w|--warn)
            level="[WARN]"
            message="${*:2}"
            color_level="\033[0;33m"
            color_message="\033[0;96m"
            color_time="\033[0;33m"
            syslog_severity="warning"
            ;;
        -e|--error)
            level="[ERROR]"
            message="${*:2}"
            color_level="\033[0;31m"
            color_message="\033[0;96m"
            color_time="\033[0;33m"
            syslog_severity="err"
            ;;
        -d|--debug)
            level="[DEBUG]"
            message="${*:2}"
            color_level="\033[0;36m"
            color_message="\033[0;96m"
            color_time="\033[0;33m"
            syslog_severity="debug"
            ;;
        -t|--trace)
            level="[TRACE]"
            message="${*:2}"
            color_level="\033[0;37m"
            color_message="\033[0;96m"
            color_time="\033[0;33m"
            syslog_severity="debug"
            ;;
        *)
            level="[UNKNOWN]"
            message="$*"
            color_level="\033[0m"
            color_message="\033[0;96m"
            color_time="\033[0;33m"
            syslog_severity="notice"
            usage
            ;;
    esac

    # Log to both the terminal and the specified log file with color formatting
    echo -e "$color_time$(date +'%Y-%m-%d %H:%M:%S') $color_level$level\033[0m - $color_message$message\033[0m"

    # Additionally, log to syslog with the specified severity level, including the level text
    logger -p "user.$syslog_severity" -t "$0" "[$pid] $level $message"

}


usage() {
    # Checks if the script is run as root and exits with an error if not.
    # This ensures the script has necessary permissions for system configuration modification.
    # If not run as root, it prints an error message to standard error and exits with a status code of 1.


    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root" 1>&2
        exit 1
    fi
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
        echo "  -i, --install <package_names>   Installs specified packages. Multiple packages can be specified separated by spaces."
        echo "  -r, --remove <package_names>    Removes specified packages. Multiple packages can be specified separated by spaces."
        echo "  -h, --help                      Displays this help information and exits."
        echo ""
        echo "Examples:"
        echo "  upm --update                    Update the system's package list and install updates."
        echo "  upm --clean                     Clean up unnecessary packages and cache."
        echo "  upm --install nano vim          Install 'nano' and 'vim' packages."
        echo "  upm --remove nano vim           Remove 'nano' and 'vim' packages."
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
                update_host
                ;;
            -c|--clean)
                log --info "Cleaning the cache for ${PKG_MANAGER}..."
                clean_pkg_manager_cache
                remove_orphaned_package
                ;;
            -i|--install)
                shift
                packages=("$@")
                log --info "Installing packages: ${packages[*]}"
                install_package "${packages[@]}"
                break
                ;;
            -r|--remove)
                shift
                packages=("$@")
                log --info "Removing packages: ${packages[*]}"
                remove_c "${packages[@]}"
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
    # Configure the firewall to allow or deny specific traffic.
    # Enables and starts firewalld service, sets default target to DROP for all zones,
    # adds specified ports and protocols to the firewall rules, and handles allowed/denied IPs.

    usage() {
        echo "Usage: configure_firewall [options]"
        echo "Options:"
        echo "  --enable                  Enable firewalld service"
        echo "  --start                   Start firewalld service"
        echo "  --reload                  Reload firewalld rules"
        echo "  --drop-all                Drop all inbound traffic by default"
        echo "  --port &lt;port&gt;             Specify port to allow"
        echo "  --protocol &lt;protocol&gt;     Specify protocol for the port"
        echo "  --allow-inbound &lt;IP&gt;      Allow inbound traffic from IP"
        echo "  --allow-outbound &lt;IP&gt;     Allow outbound traffic to IP"
        echo "  --deny-inbound &lt;IP&gt;       Deny inbound traffic from IP"
        echo "  --deny-outbound &lt;IP&gt;      Deny outbound traffic to IP"
        echo "Example:"
        echo "  configure_firewall --enable --start --port 80 --protocol tcp"
    }


    drop_all_inbound_traffic() {
        # Set default target to DROP for all firewall zones.
        # Iterates over each zone and applies the DROP policy.

        zones=$(firewall-cmd --get-zones)

        for zone in $zones; do
            firewall-cmd --permanent --zone="$zone" --set-target=DROP
            log --info "Default target for $zone set to DROP."
        done
    }


    allow_ip_inbound() {
        local ip_list=("$@")
        for ip in "${ip_list[@]}"; do
            firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$ip' accept"
            log --info "Allowed inbound IP: $ip"
        done
    }


    allow_ip_outbound() {
        local ip_list=("$@")
        for ip in "${ip_list[@]}"; do
            firewall-cmd --permanent --add-rich-rule="rule family='ipv4' destination address='$ip' accept"
            log --info "Allowed outbound IP: $ip"
        done
    }


    deny_ip_inbound() {
        local ip_list=("$@")
        for ip in "${ip_list[@]}"; do
            firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$ip' drop"
            log --info "Denied inbound IP: $ip"
        done
    }


    deny_ip_outbound() {
        local ip_list=("$@")
        for ip in "${ip_list[@]}"; do
            firewall-cmd --permanent --add-rich-rule="rule family='ipv4' destination address='$ip' drop"
            log --info "Denied outbound IP: $ip"
        done
    }

    allowed_ips=()
    denied_ips=()

    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --enable)
                systemctl enable firewalld
                ;;
            --start)
                systemctl start firewalld
                ;;
            --reload)
                firewall-cmd --reload
                ;;
            --drop-all)
                drop_all_inbound_traffic
                ;;
            --port)
                port="$2"
                shift
                ;;
            --protocol)
                protocol="$2"
                shift
                ;;
            --allow-inbound)
                allowed_ips+=("$2")
                shift
                ;;
            --allow-outbound)
                allowed_ips+=("$2")
                shift
                ;;
            --deny-inbound)
                denied_ips+=("$2")
                shift
                ;;
            --deny-outbound)
                denied_ips+=("$2")
                shift
                ;;
            *)
                usage
                log --warn "Unknown option: $1"
                exit 1
                ;;
        esac
        shift
    done

    if [[ -n "$port" && -n "$protocol" ]]; then
        if firewall-cmd --query-port="$port/$protocol" > /dev/null 2>&1; then
            log --warn "Port $port/$protocol is already added to the firewall rules."
        else
            firewall-cmd --add-port="$port/$protocol" --permanent > /dev/null 2>&1
            log --info "Port $port/$protocol has been added to the firewall rules."
        fi
    fi

    if [[ ${#allowed_ips[@]} -gt 0 ]]; then
        allow_ip_inbound "${allowed_ips[@]}"
        allow_ip_outbound "${allowed_ips[@]}"
    fi

    if [[ ${#denied_ips[@]} -gt 0 ]]; then
        deny_ip_inbound "${denied_ips[@]}"
        deny_ip_outbound "${denied_ips[@]}"
    fi

    firewall-cmd --reload > /dev/null 2>&1
    log --info "Firewall rules have been reloaded."
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


install_ama_agent() {
    # Attempts to set up Azure Sentinel connector.
    # Checks if syslog ports (514 or 6514) are already in use.
    # If not, downloads and executes Azure Sentinel connector setup script.
    # Logs outcome of checks and actions for transparency in setup process.

    if ss -tulpn | grep -E ":6?514\b"; then
        log --info "Port 514 or 6514 is open and listening."
    else
        log --info "Port 514 or 6514 is not open."
        log --info "Setting up Azure Sentinel connector..."
        wget -O Forwarder_AMA_installer.py https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/DataConnectors/Syslog/Forwarder_AMA_installer.py
        python3 Forwarder_AMA_installer.py
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
    # policies if applicable. Logs actions and SELinux status. Accepts service
    # names as positional parameters.

    usage() {
        echo "Usage: configure_selinux [options]"
        echo "This script must be run as root."
        echo "Options:"
        echo "  -b, --bootstrap   Review all running services and create"
        echo "                    custom SELinux policies as needed."
        echo "  -s, --service     Specify one or more services to create"
        echo "                    custom SELinux policies."
        echo "  -h, --help        Display this help and exit."
        echo ""
        echo "Examples:"
        echo "  configure_selinux --bootstrap"
        echo "  configure_selinux --service firewalld rsyslog"
    }


    # Parse command-line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -b|--bootstrap)
                # Get running services for bootstrap option
                readarray -t services < <(systemctl list-units --type=service --state=running |\
                     grep -o -E "\w+.service" | sed -E "s/\..*//g")
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
                log --info "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done


    create_selinux_policy_for_service() {
        # This function creates and applies a custom SELinux policy for a specified
        # service. It restarts the service to generate SELinux denials, which are
        # then used to create a custom policy module.

        usage() {
            echo "Usage: create_selinux_policy_for_service &lt;service-name&gt;"
            echo "Creates and applies a custom SELinux policy for the specified service."
            echo "Arguments:"
            echo "  <service-name>  The name of the service for which to create the policy."
        }

        local service_name=$1

        if [[ -z "$service_name" ]]; then
            log --info "Usage: create_selinux_policy_for_service <service-name>"
            usage
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


    if ! command -v sestatus &> /dev/null; then
        log --info "SELinux is not installed. Skipping SELinux configurations."
        return
    fi

    log --info "SELinux is installed, proceeding with SELinux port configuration."
    log --info "Setting SELinux to permissive mode to collect denials."
    setenforce 0

    log --info "Services to review: ${services[*]}"
    for service in "${services[@]}"; do
        log --info "Generating SELinux policy module for ${service}."
        create_selinux_policy_for_service "$service" > /dev/null 2>&1
        log --info "Custom SELinux policy for $service has been created and applied."
    done

    log --info "Setting SELinux back to enforcing mode."
    setenforce 1

    log --info "Setting SELinux to enforcing mode in the configuration file."
    sed -E -i 's/SELINUX=(disabled|permissive)/SELINUX=enforcing/g' /etc/selinux/config

}


config_builder() {
    local config_path=$1
    local config_content=$2
    local config_name=$3

    log --info "Checking and updating ${config_name} configuration as necessary..."

    mkdir -p "$(dirname "$config_path")"

    if [ -f "$config_path" ]; then
        existing_content=$(cat "$config_path")

        cp --force "$config_path" "${config_path}.bak" >/dev/null 2>&1

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


add_cron_job_if_not_exists() {
    local cron_string=""
    local command=""

    usage() {
        echo "Usage: add_cron_job_if_not_exists --cron-string '&lt;cron_string&gt;' --command '&lt;command&gt;'"
    }


    # Parse the command line arguments
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --cron-string)
                shift
                cron_string="$1"
                ;;
            --command)
                shift
                command="$1"
                ;;
            *)
                echo "Unknown option: $1"
                echo "Usage: add_cron_job_if_not_exists --cron-string '<cron_string>' --command '<command>'"
                return 1
                ;;
        esac
        shift
    done

    # Check if the required arguments are provided
    if [ -z "$cron_string" ] || [ -z "$command" ]; then
        log --error "Error: Both --cron-string and --command must be provided."
        usage
        return 1
    fi

    local cron_job="$cron_string $command"

    if ! (crontab -l 2>/dev/null | grep -Fq "$cron_job"); then
        (crontab -l 2>/dev/null; echo "$cron_job") | crontab -
        log --info  "Cron job added: $cron_job"
    else
        log --info  "Cron job already exists: $cron_job"
    fi
}
