#!/bin/bash

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
}


# Check and prompt user to create required files
check_required_files() {
    if [ ! -f "devices.text" ]; then
        echo "Error: 'devices.text' file not found in the current directory."
        echo "Please create 'devices.text' with the following format:"
        echo "username=root, password=Embe1mpls"
        echo "10.155.0.53:57400"
        exit 1
    fi

    if [ ! -f "sensor.text" ]; then
        echo "Error: 'sensor.text' file not found in the current directory."
        echo "Please create 'sensor.text' with the following format:"
        echo "/junos/system/linecard/cpu/memory"
        echo "/interfaces/interface/state/"
        exit 1
    fi
}

# Validate files exist
check_required_files

# Function to validate Telegraf configuration using --test command
validate_telegraf_config() {
    config_file="$1"
    echo "Validating the generated Telegraf configuration..."
    sudo telegraf --config "$config_file" --test
    if [[ $? -eq 0 ]]; then
        echo "Telegraf configuration is valid."
    else
        echo "Telegraf configuration contains errors."
        troubleshoot_telegraf
    fi
}

# Function to copy the generated Telegraf configuration to /etc/telegraf/
copy_telegraf_config() {
    config_file="$1"
    target_dir="/etc/telegraf/"
    log_dir="/var/log/telegraf/"

    # Check if the target directory exists
    if [[ ! -d "$target_dir" ]]; then
        echo "Directory $target_dir does not exist. Creating it..."
        sudo mkdir -p "$target_dir"
    fi

    # Copy the configuration file
    echo "Copying $config_file to $target_dir"
    sudo cp "$config_file" "$target_dir"

    # Handle ownership for Telegraf service
    if id "_telegraf" &>/dev/null; then
        sudo chown _telegraf:_telegraf "$target_dir$config_file"
    else
        echo "_telegraf user does not exist, using root ownership."
        sudo chown root:root "$target_dir$config_file"
    fi

    # Ensure the log directory exists and has the correct permissions
    if [[ ! -d "$log_dir" ]]; then
        echo "Creating Telegraf log directory: $log_dir"
        sudo mkdir -p "$log_dir"
    fi

    # Set correct ownership and permissions for the log directory
    sudo chown _telegraf:_telegraf "$log_dir"
    sudo chmod 755 "$log_dir"

    if [[ $? -eq 0 ]]; then
        echo "$config_file has been successfully copied to $target_dir"
    else
        echo "Failed to copy $config_file to $target_dir"
        exit 1
    fi
}

# Function to update the telegraf.service file to use the new config
update_telegraf_service() {
    echo "Updating telegraf.service to use the new configuration file"
    sudo sed -i 's|ExecStart=.*|ExecStart=/usr/bin/telegraf -config /etc/telegraf/telegraf_generated.conf|' /lib/systemd/system/telegraf.service
    echo "telegraf.service has been updated."
    
    # Reload systemd daemon and restart Telegraf
    echo "Reloading systemd daemon and restarting Telegraf service..."
    sudo systemctl daemon-reload
    sudo systemctl restart telegraf
    
    if [[ $? -eq 0 ]]; then
        echo "Telegraf service has been restarted successfully with the new configuration."
    else
        echo "Failed to restart Telegraf service."
    fi
}

# Function to read sensor paths from sensor.text
read_sensor_paths() {
    if [ ! -f "sensor.text" ]; then
        echo "sensor.text not found. Please ensure it exists in the current directory."
        exit 1
    fi

    echo "Available sensor paths:"
    cat -n sensor.text

    read -p "Enter '1', '2', or 'all' to select sensor paths (default 'all'): " sensor_choices
    sensor_choices=${sensor_choices:-all}

    selected_sensors=()
    if [[ "$sensor_choices" == "all" ]]; then
        while IFS= read -r sensor; do
            if [[ -n "$sensor" ]]; then
                selected_sensors+=("$sensor")
            fi
        done < sensor.text
    else
        sensor=$(sed "${sensor_choices}q;d" sensor.text)
        selected_sensors+=("$sensor")
    fi

    echo "Selected sensor paths:"
    for sensor in "${selected_sensors[@]}"; do
        echo "$sensor"
    done
}

# Function to read server addresses from devices.text
read_server_addresses() {
    if [ ! -f "devices.text" ]; then
        echo "devices.text not found. Please ensure it exists in the current directory."
        exit 1
    fi

    echo "Available server addresses:"
    cat -n devices.text | grep -v username

    read -p "Enter '1', '2', or 'all' to select server addresses (default 'all'): " server_choices
    server_choices=${server_choices:-all}

    selected_servers=()
    if [[ "$server_choices" == "all" ]]; then
        while IFS= read -r server; do
            if [[ -n "$server" && ! $server =~ username ]]; then
                selected_servers+=("\"$server\"")
            fi
        done < devices.text
    else
        server=$(sed "${server_choices}q;d" devices.text | grep -v username)
        selected_servers+=("\"$server\"")
    fi

    echo "Selected server addresses:"
    for server in "${selected_servers[@]}"; do
        echo "$server"
    done
}


generate_gnmi_input() {
    echo "[[inputs.gnmi]]"
    if [ ${#selected_servers[@]} -gt 0 ]; then
        echo "  addresses = [$(IFS=,; echo "${selected_servers[*]}")]"
    else
        echo "  addresses = []"
    fi
    echo "  username = \"root\""
    echo "  password = \"Embe1mpls\""
    echo "  encoding = \"proto\""
    echo "  redial = \"10s\""

    local index=1
    for sensor in "${selected_sensors[@]}"; do
        if [[ -n "$sensor" ]]; then
            echo "  [[inputs.gnmi.subscription]]"
            echo "    name = \"sensor_${index}\""  # Generate a unique name
            echo "    path = \"$sensor\""
            echo "    subscription_mode = \"sample\""
            echo "    sample_interval = \"10s\""
            ((index++))  # Increment the index for the next subscription
        fi
    done
}



# Function to generate JTI input configuration
generate_jti_input() {
    echo "[[inputs.jti_openconfig_telemetry]]"
    if [ ${#selected_servers[@]} -gt 0 ]; then
        echo "  servers = [$(IFS=,; echo "${selected_servers[*]}")]"
    else
        echo "  servers = []"
    fi
    echo "  sample_frequency = \"10000ms\""
    echo "  username = \"root\""
    echo "  password = \"Embe1mpls\""
    echo "  client_id = \"Switch\""
    echo "  sensors = ["

    for sensor in "${selected_sensors[@]}"; do
        if [[ -n "$sensor" ]]; then
            echo "    \"$sensor\","
        fi
    done
    echo "  ]"
}

# Function to generate Prometheus client output configuration
generate_prometheus_output() {
    echo "[[outputs.prometheus_client]]"
    echo "  listen = \":9273\""
    echo "  path = \"/metrics\""
}

# Function to generate common agent configuration
generate_agent_config() {
    echo "[agent]"
    echo "  interval = \"10s\""
    echo "  round_interval = true"
    echo "  metric_batch_size = 1000"
    echo "  metric_buffer_limit = 10000"
    echo "  collection_jitter = \"0s\""
    echo "  flush_interval = \"10s\""
    echo "  flush_jitter = \"0s\""
    echo "  precision = \"0s\""
    echo "  logfile = \"/var/log/telegraf/telegraf.log\""
    echo "  omit_hostname = false"
    echo "  debug = true"
}


# Function to generate otel-collector-config.yaml
generate_otelcol_config() {
    cat > otel-collector-config.yaml <<EOF
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
EOF

    echo "otel-collector-config.yaml has been generated."

    # Run OpenTelemetry Collector in the background
    nohup otelcol --config otel-collector-config.yaml > otelcol.log 2>&1 &
    echo "OpenTelemetry Collector started with configuration from otel-collector-config.yaml"
}


# Function to generate OpenTelemetry output configuration
generate_opentelemetry_output() {
    echo "[[outputs.opentelemetry]]"
    echo "  service_address = \"0.0.0.0:4317\""
}



# Main function to generate the Telegraf configuration, copy it, and update the service
generate_telegraf_config_and_apply() {
    # Read sensor paths and server addresses
    read_sensor_paths
    read_server_addresses

    echo "Please select an input plugin:"
    echo "1) gNMI"
    echo "2) JTI"
    read -p "Enter your choice (1 or 2): " input_choice

    echo "Please select an output plugin:"
    echo "1) OpenTelemetry"
    echo "2) Prometheus Client"
    read -p "Enter your choice (1 or 2): " output_choice

    # Create a new telegraf config file
    config_file="telegraf_generated.conf"
    > $config_file

    # Generate the input plugin configuration
    if [[ "$input_choice" == "1" ]]; then
        generate_gnmi_input >> $config_file
    elif [[ "$input_choice" == "2" ]]; then
        generate_jti_input >> $config_file
    else
        echo "Invalid input plugin selection."
        exit 1
    fi

    # Generate the output plugin configuration
    if [[ "$output_choice" == "1" ]]; then
        generate_opentelemetry_output >> $config_file
	generate_otelcol_config
    elif [[ "$output_choice" == "2" ]]; then
        generate_prometheus_output >> $config_file
    else
        echo "Invalid output plugin selection."
        exit 1
    fi

    # Generate the common agent configuration
    generate_agent_config >> $config_file

    echo "Telegraf configuration has been generated and saved to $config_file"

    # Validate the generated configuration
    validate_telegraf_config "$config_file"
    
    # Copy the generated config to /etc/telegraf/
    copy_telegraf_config "$config_file"
    
    # Update telegraf.service to use the new config
    update_telegraf_service
}

# Main menu loop
while true; do
    echo "Choose an action:"
    echo "1) Generate and apply Telegraf configuration"
    echo "2) Troubleshoot Telegraf"
    echo "3) Back to main script (setup_telemetry.sh)"
    read -p "Enter your choice: " choice

    case $choice in
        1)
            check_required_files
            generate_telegraf_config_and_apply
            ;;
        2)
            troubleshoot_telegraf
            ;;
        3)
            echo "Returning to main script..."
            exit 0  # Exit config_telegraf.sh to return to run_telemetry.sh
            ;;
        *)
            echo "Invalid choice. Please try again."
            ;;
    esac
    echo # Blank line for readability
done

