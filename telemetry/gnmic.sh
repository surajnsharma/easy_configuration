#!/bin/bash

# Define paths for gnmic binary, devices, and sensor files
GNMIC_PATH="/usr/local/bin/gnmic"  # Set this to the correct path of the gnmic binary
DEVICES_FILE="devices.text"
SENSOR_FILE="sensor.text"

# Function to read device credentials and addresses from devices.text
read_devices_and_credentials() {
    if [[ ! -f "$DEVICES_FILE" ]]; then
        echo "Devices file $DEVICES_FILE not found!"
        exit 1
    fi

    # Extract credentials
    username=$(grep -oP '(?<=username=)[^,]*' "$DEVICES_FILE")
    password=$(grep -oP '(?<=password=)[^,]*' "$DEVICES_FILE")

    # Display devices excluding lines with credentials
    echo "Available devices:"
    grep -Ev "username|password" "$DEVICES_FILE" | cat -n
    read -p "Select device(s) to subscribe (enter 'all' for all devices): " device_choice

    if [[ "$device_choice" == "all" ]]; then
        selected_devices=($(grep -Ev "username|password" "$DEVICES_FILE"))
    else
        selected_devices=($(grep -Ev "username|password" "$DEVICES_FILE" | sed -n "${device_choice}p"))
    fi
}

# Function to read sensor paths from sensor.text
read_sensors() {
    if [[ ! -f "$SENSOR_FILE" ]]; then
        echo "Sensors file $SENSOR_FILE not found!"
        exit 1
    fi

    echo "Available sensor paths:"
    cat -n "$SENSOR_FILE"
    read -p "Select sensor path(s) (enter 'all' for all paths): " sensor_choice

    if [[ "$sensor_choice" == "all" ]]; then
        selected_sensors=($(cat "$SENSOR_FILE"))
    else
        selected_sensors=($(sed -n "${sensor_choice}p" "$SENSOR_FILE"))
    fi
}

# Function to execute subscribe RPC with a timeout and save output
execute_subscribe_once() {
    # Append to gnmic_telemetry.log instead of overwriting
    echo "=========================" >> gnmic_telemetry.log
    echo "New subscription session: $(date)" >> gnmic_telemetry.log
    echo "=========================" >> gnmic_telemetry.log

    for device in "${selected_devices[@]}"; do
        echo "Subscribing to device: $device" | tee -a gnmic_telemetry.log
        paths=""
        for sensor in "${selected_sensors[@]}"; do
            paths+=" --path $sensor"
        done
        # Run the subscription with a timeout and append output to file
        timeout 10 "$GNMIC_PATH" -a "$device" -u "$username" -p "$password" --insecure subscribe $paths --encoding json >> gnmic_telemetry.log 2>&1
        echo -e "\e[32mSubscription for $device completed and saved to gnmic_telemetry.log.\e[0m" | tee -a gnmic_telemetry.log
    done
}

# Function to execute the subscription multiple times based on user input
execute_multiple_subscriptions() {
    read -p "Enter the number of iterations for collecting telemetry data: " num_iterations
    for ((i=1; i<=num_iterations; i++)); do
        echo -e "\n\e[34mIteration $i of $num_iterations:\e[0m"
        execute_subscribe_once
        sleep 1  # Add delay if required between iterations
    done
}

# Main function to prompt user actions
main() {
    echo "Choose an action:"
    echo "1) Subscribe to telemetry data and save to file"
    echo "2) Back to main script (run_telemetry.sh)"
    read -p "Enter your choice: " choice

    case $choice in
        1) 
            read_devices_and_credentials
            read_sensors
            execute_multiple_subscriptions
            ;;
        2)
            echo "Returning to main script..."
            exit 0  # Exit gnmic.sh to return to run_telemetry.sh
            ;;
        *)
            echo "Invalid choice. Exiting."
            ;;
    esac
    echo # Add a blank line for readability
}

# Run the main function
main

