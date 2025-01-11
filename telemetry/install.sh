#!/bin/bash


# Set variables for gnmic binary, download URL, and file paths
GNMIC_BINARY="gnmic"
LOCAL_GNMIC_PACKAGE="gnmic_0.38.2_linux_x86_64.tar.gz"  # Adjust version as needed
DOWNLOAD_URL="https://github.com/openconfig/gnmic/releases/download/v0.38.2/$LOCAL_GNMIC_PACKAGE"
GNMIC_PATH="/usr/local/bin/$GNMIC_BINARY"
DEVICES_FILE="devices.text"
SENSOR_FILE="sensor.text"
OUTPUT_FILE="gnmic_telemetry.log"

# Set default download URLs and filenames
DEFAULT_GNMIC_URL="https://github.com/openconfig/gnmic/releases/download/v0.38.2/gnmic_0.38.2_linux_x86_64.tar.gz"
DEFAULT_PROMETHEUS_URL="https://github.com/prometheus/prometheus/releases/download/v2.54.1/prometheus-2.54.1.linux-amd64.tar.gz"
DEFAULT_OTELCOL_URL="https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.111.0/otelcol_0.111.0_linux_amd64.tar.gz"


# Function to get a URL from the user or use the default if no input is provided
get_download_url() {
    local prompt="$1"
    local default_url="$2"
    read -p "$prompt (Default: $default_url): " user_url
    echo "${user_url:-$default_url}"  # Use user input if provided, otherwise the default
}


# Function to check if a service is running
check_service_status() {
    service_name=$1
    if systemctl is-active --quiet $service_name; then
        echo "$service_name is running."
        return 0
    else
        echo "$service_name is either not installed or not running."
        return 1
    fi
}

# Get URLs from user input or use defaults
#GNMIC_URL=$(get_download_url "Enter gnmic download URL" "$DEFAULT_GNMIC_URL")
#PROMETHEUS_URL=$(get_download_url "Enter Prometheus download URL" "$DEFAULT_PROMETHEUS_URL")
#OTELCOL_URL=$(get_download_url "Enter OpenTelemetry Collector download URL" "$DEFAULT_OTELCOL_URL")

# Function to derive filename from URL
get_filename_from_url() {
    local url="$1"
    echo "${url##*/}"  # Extract filename from URL
}

# Derived filenames from URLs
GNMIC_PACKAGE=$(get_filename_from_url "$GNMIC_URL")
PROMETHEUS_PACKAGE=$(get_filename_from_url "$PROMETHEUS_URL")
OTELCOL_PACKAGE=$(get_filename_from_url "$OTELCOL_URL")


# Function to download gnmic from local package if available, else download from the web
download_gnmic() {
    if [[ -f "$GNMIC_PATH" ]]; then
        echo "gnmic is already installed at $GNMIC_PATH."
    elif [[ -f "$LOCAL_GNMIC_PACKAGE" ]]; then
        echo "Local gnmic package found. Installing gnmic from local file..."
        sudo tar -xzf "$LOCAL_GNMIC_PACKAGE" -C /usr/local/bin
        if [[ -f "$GNMIC_PATH" ]]; then
            echo "gnmic installed successfully from local package."
        else
            echo "Failed to install gnmic from local package."
            exit 1
        fi
    else
        echo "Local package not found. Downloading gnmic from the web..."
        curl -sLO $DOWNLOAD_URL
        if [[ -f "$LOCAL_GNMIC_PACKAGE" ]]; then
            sudo tar -xzf "$LOCAL_GNMIC_PACKAGE" -C /usr/local/bin
            echo "gnmic downloaded and installed successfully."
        else
            echo "Failed to download gnmic."
            exit 1
        fi
    fi
}




# Function to check if a service exists
check_service_exists() {
    service_name=$1
    if systemctl list-units --all --type=service | grep -q "$service_name"; then
        return 0
    else
        echo "Service $service_name not found."
        return 1
    fi
}

# Function to wait for a service to become active
wait_for_service() {
    service_name=$1
    echo "Waiting for $service_name to become active..."

    for i in {1..60}; do
        if systemctl is-active --quiet $service_name; then
            echo "$service_name is running."
            return 0
        fi
        sleep 1
    done

    echo "$service_name failed to start within 60 seconds."
    return 1
}


# Function to check if a port is listening using netstat
check_port_status() {
    port=$1
    service_name=$2
    ip=${3:-"0.0.0.0"}  # Default IP is 0.0.0.0 if not provided

    # Check for LISTEN status on the given port using netstat
    listening=$(sudo netstat -tuln | grep ":$port" | grep "LISTEN")

    if [ ! -z "$listening" ]; then
        echo -e "\e[32m$service_name is LISTENING on port $port.\e[0m"
    else
        echo -e "\e[31m$service_name is not listening on port $port.\e[0m"
    fi
}


# Function to check Prometheus status and web link
check_prometheus_status() {
    echo "Checking Prometheus status..."
    check_port_status 9091 "prometheus-web-port"
    #echo -e "\e[38;5;222mPrometheus Web UI: http://localhost:9091\e[0m"
}


# Function to check OpenTelemetry status and port
check_opentelemetry_status() {
    echo "Checking OpenTelemetry Collector status..."
    check_port_status 9464 "otelcol-src-to-prometheus"
    check_port_status 4317 "otelcol-src-port-telegraf"
    #echo -e "\e[38;5;222mOpenTelemetry Collector scrape_configs: http://localhost:9464/metrics\e[0m"
}

# Function to check Telegraf status and port
check_telegraf_status() {
    echo "Checking Telegraf status..."
    check_port_status 9273 "telegraf-src-port-prometheus"
    #echo -e "\e[38;5;222mTelegraf scrape_configs: http://localhost:9273/metrics\e[0m"
}


# Function to provide curl links for services
provide_curl_links() {
    echo -e "You can use the following curl links to test the services"
    echo -e "\e[38;5;222mTelegraf->Prometheus-Scrape-data-> curl http://localhost:9273/metrics\e[0m"
    echo -e "\e[38;5;222mOpenTelemetry->Prometheus-Scrape-data-> curl http://localhost:9464/metrics\e[0m"
    echo -e "\e[38;5;222mPrometheus Web Link-> http://<server ip:9091\e[0m"
}

# Function to check ESTABLISHED connection between Prometheus and Telegraf on port 9273
check_telegraf_prometheus_connection() {
    prometheus_to_telegraf=$(sudo lsof -i :9273 | grep -i "prometh" | grep "ESTABLISH")
    telegraf_to_prometheus=$(sudo lsof -i :9273 | grep -i "tele" | grep "ESTABLISH")

    if [[ ! -z "$prometheus_to_telegraf" ]]; then
        echo -e "\e[32mPrometheus has an ESTABLISHED connection to Telegraf on port 9273.\e[0m"
    else
        echo -e "\e[31mNo ESTABLISHED connection found from Prometheus to Telegraf on port 9273.\e[0m"
    fi

    if [[ ! -z "$telegraf_to_prometheus" ]]; then
        echo -e "\e[32mTelegraf has an ESTABLISHED connection to Prometheus on port 9273.\e[0m"
    else
        echo -e "\e[31mNo ESTABLISHED connection found from Telegraf to Prometheus on port 9273.\e[0m"
    fi
}

# Function to check ESTABLISHED connection between Prometheus and OpenTelemetry on port 9464
check_otelcol_prometheus_connection() {
    prometheus_to_otelcol=$(sudo lsof -i :9464 | grep -i "prometh" | grep "ESTABLISHED")
    otelcol_to_prometheus=$(sudo lsof -i :9464 | grep -i "otelcol" | grep "ESTABLISHED")

    if [[ ! -z "$prometheus_to_otelcol" ]]; then
        echo -e "\e[32mPrometheus has an ESTABLISHED connection to OpenTelemetry on port 9464.\e[0m"
    else
        echo -e "\e[31mNo ESTABLISHED connection found from Prometheus to OpenTelemetry on port 9464.\e[0m"
    fi

    if [[ ! -z "$otelcol_to_prometheus" ]]; then
        echo -e "\e[32mOpenTelemetry has an ESTABLISHED connection to Prometheus on port 9464.\e[0m"
    else
        echo -e "\e[31mNo ESTABLISHED connection found from OpenTelemetry to Prometheus on port 9464.\e[0m"
    fi
}

# Function to check ESTABLISHED connection between OpenTelemetry and Telegraf on port 4317
check_otelcol_telegraf_connection() {
    otelcol_to_telegraf=$(sudo lsof -i :4317 | grep "otelcol" | grep "ESTABLISHED")
    telegraf_to_otelcol=$(sudo lsof -i :4317 | grep "telegraf" | grep "ESTABLISHED")

    if [[ ! -z "$otelcol_to_telegraf" && ! -z "$telegraf_to_otelcol" ]]; then
        echo -e "\e[32mESTABLISHED connection found between otelcol and Telegraf on port 4317.\e[0m"
    else
        echo -e "\e[31mNo ESTABLISHED connection found between otelcol and Telegraf on port 4317.\e[0m"
    fi
}

# Function to retrieve the installed version of a service
get_installed_version() {
    service_name=$1
    case "$service_name" in
        otelcol)
            if command -v otelcol &> /dev/null; then
                otelcol --version
            else
                echo "Unable to retrieve version information for $service_name."
            fi
            ;;
        prometheus)
            if command -v prometheus &> /dev/null; then
                prometheus --version | head -n 1
            else
                echo "Unable to retrieve version information for $service_name."
            fi
            ;;
        telegraf)
            if command -v telegraf &> /dev/null; then
                telegraf --version
            else
                echo "Unable to retrieve version information for $service_name."
            fi
            ;;
        *)
            echo "No version information available for $service_name."
            ;;
    esac
}

# Function to ask user if they want to reinstall or skip
prompt_for_reinstall() {
    service_name=$1

    # Show current version if installed
    echo "$service_name is already installed. Current version:"
    get_installed_version "$service_name"

    while true; do
        read -p "Do you want to reinstall $service_name? (y/n): " user_choice
        case "$user_choice" in
            y|Y|yes|Yes )
                return 0  # Reinstall the service
                ;;
            n|N|no|No )
                return 1  # Skip the installation
                ;;
            * )
                echo "Invalid input. Please enter 'y' or 'n'."
                ;;
        esac
    done
}


# Function to restart a service
restart_service() {
    service_name=$1

    # Check if service exists
    if ! check_service_exists "$service_name"; then
        echo "Skipping restart for $service_name since it does not exist."
        return 1
    fi

    echo "Restarting $service_name..."
    sudo systemctl restart $service_name

    # Check if the service restarted successfully
    if systemctl is-active --quiet $service_name; then
        echo -e "\e[32m$service_name restarted successfully.\e[0m"
    else
        echo -e "\e[31mFailed to restart $service_name.\e[0m"
        return 1
    fi
}


# Function to start a service
start_service() {
    service_name=$1

    # Check if service exists
    if ! check_service_exists "$service_name"; then
        echo "Skipping start for $service_name since it does not exist."
        return 1
    fi

    echo "Starting $service_name..."
    sudo systemctl start $service_name

    # Check if the service started successfully
    if systemctl is-active --quiet $service_name; then
        echo -e "\e[32m$service_name started successfully.\e[0m"
    else
        echo -e "\e[31mFailed to start $service_name.\e[0m"
        return 1
    fi
}


# Function to stop a service
stop_service() {
    service_name=$1

    # Check if service exists
    if ! check_service_exists "$service_name"; then
        echo "Skipping stop for $service_name since it does not exist."
        return 1
    fi

    echo "Stopping $service_name..."
    sudo systemctl stop $service_name

    # Check if the service has successfully stopped
    if systemctl is-active --quiet $service_name; then
        echo -e "\e[31mFailed to stop $service_name.\e[0m"
        return 1
    else
        echo -e "\e[32m$service_name has been stopped successfully.\e[0m"
        return 0
    fi
}


# Function to restart all services
restart_all_services() {
    restart_service "otelcol"
    restart_service "telegraf"
    restart_service "prometheus"
    main_menu
}
# Function to restart all services
stop_all_services() {
    stop_service "otelcol"
    stop_service "telegraf"
    stop_service "prometheus"
    main_menu
}
# Function to restart all services
start_all_services() {
    start_service "otelcol"
    start_service "telegraf"
    start_service "prometheus"
    main_menu
}

# Function to restart a specific service
restart_one_service() {
    read -p "Enter service name (otelcol/telegraf/prometheus): " service_name
    restart_service "$service_name"
}
# Function to restart a specific service
stop_one_service() {
    read -p "Enter service name (otelcol/telegraf/prometheus): " service_name
    stop_service "$service_name"
}
# Function to restart a specific service
start_one_service() {
    read -p "Enter service name (otelcol/telegraf/prometheus): " service_name
    start_service "$service_name"
}


# Function to uninstall a service
uninstall_service() {
    service_name=$1
    if check_service_exists "$service_name"; then
        echo "Uninstalling $service_name..."
        sudo systemctl stop $service_name
        sudo systemctl disable $service_name
        sudo rm -f /etc/systemd/system/$service_name.service
        sudo systemctl daemon-reload
        echo "$service_name uninstalled."
    else
        echo "$service_name is not installed, skipping uninstall."
    fi
}




# Function to install OpenTelemetry Collector and store sample YAML
install_opentelemetry_collector() {
    if check_service_status "otelcol"; then
        if ! prompt_for_reinstall "OpenTelemetry Collector"; then
            echo "Skipping OpenTelemetry Collector installation."
            return
        fi
    fi

    # Check if the package exists locally
    if [ ! -f "otelcol_0.111.0_linux_amd64.tar.gz" ]; then
        echo "Downloading OpenTelemetry Collector..."
        wget -O "$OTELCOL_PACKAGE" "$OTELCOL_URL"
    else
        echo "Found OpenTelemetry Collector package locally."
    fi
    
    tar -xvf otelcol_0.111.0_linux_amd64.tar.gz
    sudo mv otelcol /usr/local/bin/otelcol
    sudo chmod +x /usr/local/bin/otelcol

    # Create systemd service file for OpenTelemetry Collector
    sudo bash -c 'cat > /etc/systemd/system/otelcol.service <<EOF
[Unit]
Description=OpenTelemetry Collector
After=network.target

[Service]
ExecStart=/usr/local/bin/otelcol --config=/etc/otelcol/otel-collector-config.yaml
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF'
    sudo systemctl enable otelcol
    sudo systemctl start otelcol

    # Store the otel-collector-config.yaml in /etc/otelcol
    sudo mkdir -p /etc/otelcol
    sudo bash -c 'cat > /etc/otelcol/otel-collector-config.yaml <<EOF
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: "0.0.0.0:4317"
      http:
        endpoint: "0.0.0.0:4320"
processors:
  batch:

exporters:
  debug:
  prometheus:
    endpoint: "0.0.0.0:9464"

service:
  pipelines:
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug, prometheus]
EOF'
    echo "OpenTelemetry Collector installed and configuration file created at /etc/otelcol/otel-collector-config.yaml"

    # Log to URL.md
    echo -e "OpenTelemetry Collector configuration:\n/etc/otelcol/otel-collector-config.yaml\n" >> URL.md
    wait_for_service "otelcol"
}

# Function to install Prometheus and store sample YAML
install_prometheus() {
    if check_service_status "prometheus"; then
        if ! prompt_for_reinstall "Prometheus"; then
            echo "Skipping Prometheus installation."
            return
        fi
    fi

    # Check if Prometheus binary exists and matches the required version
    PROMETHEUS_VERSION="2.54.1"
    PROMETHEUS_BINARY="/usr/local/bin/prometheus"
    PROMETHEUS_PACKAGE="prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz"
    PROMETHEUS_URL="https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/${PROMETHEUS_PACKAGE}"

    if [ -f "$PROMETHEUS_BINARY" ]; then
        INSTALLED_VERSION=$($PROMETHEUS_BINARY --version | head -n 1 | grep -oP '\d+\.\d+\.\d+')
        if [ "$INSTALLED_VERSION" == "$PROMETHEUS_VERSION" ]; then
            echo "Prometheus $INSTALLED_VERSION is already installed."
        else
            echo "Prometheus version mismatch. Updating to $PROMETHEUS_VERSION..."
            sudo rm -f "$PROMETHEUS_BINARY"
        fi
    fi

    # Download and extract Prometheus if needed
    if [ ! -f "$PROMETHEUS_BINARY" ]; then
        if [ ! -f "$PROMETHEUS_PACKAGE" ]; then
            echo "Downloading Prometheus..."
            wget -O "$PROMETHEUS_PACKAGE" "$PROMETHEUS_URL"
        else
            echo "Found Prometheus package locally."
        fi

        echo "Extracting Prometheus package..."
        tar -xvf "$PROMETHEUS_PACKAGE"
        sudo mv prometheus-${PROMETHEUS_VERSION}.linux-amd64/prometheus /usr/local/bin/
        sudo chmod +x /usr/local/bin/prometheus
        echo "Prometheus binary copied to /usr/local/bin/"
    fi

    # Create Prometheus systemd service
    echo "Creating Prometheus systemd service..."
    sudo bash -c 'cat > /etc/systemd/system/prometheus.service <<EOF
[Unit]
Description=Prometheus Monitoring
After=network.target

[Service]
ExecStart=/usr/local/bin/prometheus --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/var/lib/prometheus --web.listen-address="0.0.0.0:9091"
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF'

    # Enable and start Prometheus service
    echo "Enabling and starting Prometheus service..."
    sudo systemctl daemon-reload
    sudo systemctl enable prometheus
    sudo systemctl start prometheus

    # Verify service status
    if systemctl is-active --quiet prometheus; then
        echo "Prometheus service started successfully."
    else
        echo "Failed to start Prometheus service. Check logs for details."
        sudo journalctl -u prometheus -xe
    fi

    # Create Prometheus configuration directory and default configuration file
    echo "Configuring Prometheus..."
    sudo mkdir -p /etc/prometheus
    sudo bash -c 'cat > /etc/prometheus/prometheus.yml <<EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "telegraf"
    static_configs:
      - targets: ["0.0.0.0:9273"]

  - job_name: "opentelemetry-collector"
    static_configs:
      - targets: ["0.0.0.0:9464"]
EOF'

    echo "Prometheus configuration file created at /etc/prometheus/prometheus.yml"

    # Log to URL.md
    echo -e "Prometheus configuration:\n/etc/prometheus/prometheus.yml\n" >> URL.md

    # Wait for Prometheus service to start
    wait_for_service "prometheus"
}



# Function to install Telegraf
install_telegraf() {
    if check_service_status "telegraf"; then
        if ! prompt_for_reinstall "Telegraf"; then
            echo "Skipping Telegraf installation."
            return
        fi
    fi

    echo "Adding InfluxData repository for Telegraf installation..."
    # Add InfluxData repository
    curl -sL https://repos.influxdata.com/influxdb.key | sudo apt-key add -
    echo "deb https://repos.influxdata.com/ubuntu focal stable" | sudo tee /etc/apt/sources.list.d/influxdb.list

    echo "Updating package lists..."
    sudo apt-get update

    echo "Attempting to install Telegraf using apt-get..."
    if sudo apt-get install -y telegraf; then
        echo -e "\e[32mTelegraf installed successfully using apt-get.\e[0m"
    else
        echo -e "\e[31mFailed to install Telegraf using apt-get. Falling back to manual installation.\e[0m"

        # Manual installation fallback
        TELEGRAF_VERSION="1.27.4"
        TELEGRAF_URL="https://dl.influxdata.com/telegraf/releases/telegraf_${TELEGRAF_VERSION}-1_amd64.deb"

        echo "Downloading Telegraf version ${TELEGRAF_VERSION}..."
        wget "$TELEGRAF_URL" -O telegraf_${TELEGRAF_VERSION}.deb

        echo "Installing Telegraf manually..."
        sudo dpkg -i telegraf_${TELEGRAF_VERSION}.deb
        sudo apt-get -f install -y
    fi

    # Enable and start Telegraf service
    echo "Enabling and starting Telegraf service..."
    sudo systemctl enable telegraf
    sudo systemctl start telegraf

    # Check service status
    if systemctl is-active --quiet telegraf; then
        echo -e "\e[32mTelegraf installed and running successfully.\e[0m"
    else
        echo -e "\e[31mFailed to start Telegraf. Check the logs for more information.\e[0m"
        troubleshoot_telegraf
    fi

    echo -e "Telegraf configuration path:\n/etc/telegraf/telegraf.conf\n" >> URL.md
    wait_for_service "telegraf"
}




# Function to uninstall gnmic
uninstall_gnmic() {
    if [[ -f "$GNMIC_PATH" ]]; then
        echo "Uninstalling gnmic..."
        sudo rm -f "$GNMIC_PATH"
        
        if [[ ! -f "$GNMIC_PATH" ]]; then
            echo "gnmic uninstalled successfully."
        else
            echo "Failed to uninstall gnmic."
            exit 1
        fi
    else
        echo "gnmic is not installed."
    fi
}


uninstall_services() {
    while true; do
        echo "Choose services to uninstall:"
        echo "1) Telegraf"
        echo "2) Prometheus"
        echo "3) OpenTelemetry Collector"
        echo "4) gnmic"
        echo "5) All"
        echo "6) Back to main menu"
        read -p "Enter your choice (e.g., 1 3 for Telegraf and OpenTelemetry): " uninstall_choice

        case $uninstall_choice in
            *1*) uninstall_service "telegraf" ;;
            *2*) uninstall_service "prometheus" ;;
            *3*) uninstall_service "otelcol" ;;
            *4*) uninstall_gnmic ;;
            5)
                uninstall_service "telegraf"
                uninstall_service "prometheus"
                uninstall_service "otelcol"
                uninstall_gnmic
                ;;
            6)
                echo "Returning to main menu..."
                main_menu
                break
                ;;
            *) echo "Invalid choice. Please try again." ;;
        esac
    done
}



# Function to check the status of all services
check_services_status() {
    echo "Checking the status of all services..."
    
    # Check Telegraf status
    check_telegraf_status
    
    # Check OpenTelemetry status
    check_opentelemetry_status
    
    # Check Prometheus web link
    check_prometheus_status
    
    # Check for ESTABLISHED connections between Prometheus and Telegraf
    check_telegraf_prometheus_connection

    # Check for ESTABLISHED connections between Prometheus and OpenTelemetry
    check_otelcol_prometheus_connection
    
    # Check for ESTABLISHED connections between OpenTelemetry and Telegraf
    check_otelcol_telegraf_connection

    # Provide curl links for testing
    provide_curl_links
    echo -e "\nConfiguration file paths:"
    echo "OpenTelemetry Collector: /etc/otelcol/otel-collector-config.yaml"
    echo "Telegraf: /etc/telegraf/telegraf.conf"
    echo "Prometheus: /etc/prometheus/prometheus.yml"
     main_menu
}


# Function to provide troubleshooting steps for Telegraf
troubleshoot_telegraf() {
    echo -e "\nIt looks like there was an error with Telegraf. Here are some troubleshooting steps you can try:"
    echo "1. View logs to see the specific error:"
    echo "   sudo journalctl -u telegraf -f"
    echo "2. Test your configuration:"
    echo "   sudo telegraf --config /etc/telegraf/telegraf_generated.conf --test"
    echo "3. Run a configuration test on the default config file:"
    echo "   sudo telegraf --config /etc/telegraf/telegraf.conf --test"
    echo "4. Tail the Telegraf log file to monitor real-time events:"
    echo "   sudo tail -f /var/log/telegraf/telegraf.log"
    echo "5. Check active connections on port 4317 (for OpenTelemetry):"
    echo "   sudo lsof -i :4317"
    echo "6. Restart the Telegraf service:"
    echo "   sudo systemctl restart telegraf"
    echo "7. Stop the Telegraf service:"
    echo "   sudo systemctl stop telegraf"
    echo "8. Check the status of Telegraf:"
    echo "   sudo systemctl status telegraf"
    echo "9. Start the Telegraf service:"
    echo "   sudo systemctl start telegraf"
    echo "10. Verify Prometheus scraping of Telegraf metrics:"
    echo "   curl http://localhost:9273/metrics"
    echo "11. Kill all Telegraf processes if needed to reset:"
    echo "   sudo pkill telegraf"
    main_menu
}




# Function to install services
install_services() {
    # Only prompt for URLs when the user chooses to install services
    GNMIC_URL=$(get_download_url "Enter gnmic download URL" "$DEFAULT_GNMIC_URL")
    PROMETHEUS_URL=$(get_download_url "Enter Prometheus download URL" "$DEFAULT_PROMETHEUS_URL")
    OTELCOL_URL=$(get_download_url "Enter OpenTelemetry Collector download URL" "$DEFAULT_OTELCOL_URL")

    # Derived filenames from URLs
    GNMIC_PACKAGE=$(get_filename_from_url "$GNMIC_URL")
    PROMETHEUS_PACKAGE=$(get_filename_from_url "$PROMETHEUS_URL")
    OTELCOL_PACKAGE=$(get_filename_from_url "$OTELCOL_URL")

    while true; do
        echo "Choose services to install:"
        echo "1) Telegraf"
        echo "2) Prometheus"
        echo "3) OpenTelemetry Collector"
        echo "4) gnmic"
        echo "5) All"
        echo "6) Back to main menu"
        read -p "Enter your choice (e.g., 1 3 for Telegraf and OpenTelemetry): " install_choice

        case $install_choice in
            *1*) install_telegraf ;;
            *2*) install_prometheus ;;
            *3*) install_opentelemetry_collector ;;
            *4*) download_gnmic ;;
            5) 
                install_telegraf
                install_prometheus
                install_opentelemetry_collector
                download_gnmic
                ;;
            6) 
                echo "Returning to main menu..."
                main_menu
                break
                ;;
            *) echo "Invalid choice. Please try again." ;;
        esac
    done
}



# Main menu
main_menu() {
    echo "Choose an action:"
    echo "1) Install services"
    echo "2) Uninstall services"
    echo "3) Check status of services"
    echo "4) Restart services"
    echo "5) Stop services"
    echo "6) Start services"
    echo "7) Troubleshooting"
    echo "8) Back to main script (run_telemetry.sh)"
    read -p "Enter your choice: " user_choice
    case $user_choice in
        1) install_services ;;
        2) uninstall_services ;;
        3) check_services_status ;;
        4) restart_services_menu ;;
        5) stop_services_menu ;;
        6) start_services_menu ;;
        7) troubleshoot_telegraf ;;
        8) echo "Returning to main script..."; exit 0 ;;  # Exits install.sh
        *) echo "Invalid choice." ;;
    esac
}


# Menu for restarting services
restart_services_menu() {
    echo "Would you like to restart all services or one specific service?"
    read -p "Enter 'all' or 'one' (default is 'all'): " restart_choice

    # Set default to 'all' if user presses Enter
    restart_choice=${restart_choice:-all}

    case "$restart_choice" in
        all)
            restart_all_services
            ;;
        one)
            restart_one_service
            ;;
        *)
            echo "Invalid input. Defaulting to 'all'."
            restart_all_services
            ;;
    esac
    main_menu
}

# Menu for Stop services
stop_services_menu() {
    echo "Would you like to stop all services or one specific service?"
    read -p "Enter 'all' or 'one' (default is 'all'): " stop_choice

    # Set default to 'all' if user presses Enter
    stop_choice=${stop_choice:-all}

    case "$stop_choice" in
        all)
            stop_all_services
            ;;
        one)
            stop_one_service
            ;;
        *)
            echo "Invalid input. Defaulting to 'all'."
            stop_all_services
            ;;
    esac
    main_menu
}

# Menu for Start services
start_services_menu() {
    echo "Would you like to start all services or one specific service?"
    read -p "Enter 'all' or 'one' (default is 'all'): " stop_choice

    # Set default to 'all' if user presses Enter
    start_choice=${start_choice:-all}

    case "$stop_choice" in
        all)
            start_all_services
            ;;
        one)
            start_one_service
            ;;
        *)
            echo "Invalid input. Defaulting to 'all'."
            start_all_services
            ;;
    esac
    main_menu
}



# Run the main menu
main_menu



