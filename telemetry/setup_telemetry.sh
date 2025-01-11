#!/bin/bash
# Author: surajsharma@juniper.net
# Date: 2024-OCT-25
# Version: 1.0
# Description: Script to subscribe to telemetry data from devices using gnmic.
# This script reads device and sensor information from files, executes telemetry subscriptions,
# and saves the output to a log file.


# Define the script files
TELEGRAF_SCRIPT="config_telegraf.sh"
GNMIC_SCRIPT="gnmic.sh"
INSTALL_SCRIPT="install.sh"

# Check if each script exists in the current directory
if [[ ! -f "$TELEGRAF_SCRIPT" ]] || [[ ! -f "$GNMIC_SCRIPT" ]] || [[ ! -f "$INSTALL_SCRIPT" ]]; then
    echo "One or more required scripts are missing in the current directory."
    echo "Please ensure the following scripts are in this directory:"
    echo "  - $TELEGRAF_SCRIPT"
    echo "  - $GNMIC_SCRIPT"
    echo "  - $INSTALL_SCRIPT"
    exit 1
fi

# Function to display the menu and handle user input
run_menu() {
    while true; do
        echo "Choose a script to run:"
        echo "1) Configure Telegraf"
        echo "2) Run GNMIc"
        echo "3) Install/UnInstall/Verify"
        echo "4) Exit"
        read -p "Enter your choice (1-4): " user_choice

        case $user_choice in
            1)
                echo "Running $TELEGRAF_SCRIPT..."
                bash "$TELEGRAF_SCRIPT"
                ;;
            2)
                echo "Running $GNMIC_SCRIPT..."
                bash "$GNMIC_SCRIPT"
                ;;
            3)
                echo "Running $INSTALL_SCRIPT..."
                bash "$INSTALL_SCRIPT"
                ;;
            4)
                echo "Exiting."
                exit 0
                ;;
            *)
                echo "Invalid choice. Please try again."
                ;;
        esac
        echo # Add a blank line for better readability
    done
}

# Run the menu function
run_menu

