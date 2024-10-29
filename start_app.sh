#!/bin/bash

# Variables - update these for your environment
APP_NAME="easy_configuration"  # Name for systemd service
SERVICE_FILE="/etc/systemd/system/$APP_NAME.service"
WORKING_DIRECTORY="/root/easy_configuration"
VENV_PATH="$WORKING_DIRECTORY/venv/bin/gunicorn"
WORKERS=3
BIND_ADDRESS="0.0.0.0:8000"

# Function to create the service file if it doesn't exist
create_service_file() {
    if [ ! -f "$SERVICE_FILE" ]; then
        echo "Service file not found. Creating $SERVICE_FILE..."
        sudo bash -c "cat > $SERVICE_FILE" <<EOF
[Unit]
Description=Gunicorn instance to serve $APP_NAME with WebSockets
After=network.target

[Service]
User=root
Group=www-data
WorkingDirectory=$WORKING_DIRECTORY
Environment="FLASK_CONFIG=production"
ExecStart=$VENV_PATH --workers $WORKERS --bind $BIND_ADDRESS --worker-class eventlet "run:app"

[Install]
WantedBy=multi-user.target
EOF
        echo "$SERVICE_FILE created successfully."
        sudo systemctl daemon-reload
        sudo systemctl enable "$APP_NAME"
    else
        echo "$SERVICE_FILE already exists."
    fi
}

# Function to display menu options
show_menu() {
    echo "Choose an action:"
    echo "1) Start the application"
    echo "2) Stop the application"
    echo "3) Restart the application"
    echo "4) Check application status"
    echo "5) View application logs"
    echo "6) Exit"
}

# Function to start the application
start_app() {
    echo "Starting $APP_NAME service..."
    sudo systemctl start "$APP_NAME"
    sudo systemctl status "$APP_NAME"
}

# Function to stop the application
stop_app() {
    echo "Stopping $APP_NAME service..."
    sudo systemctl stop "$APP_NAME"
    sudo systemctl status "$APP_NAME"
}

# Function to restart the application
restart_app() {
    echo "Restarting $APP_NAME service..."
    sudo systemctl restart "$APP_NAME"
    sudo systemctl status "$APP_NAME"
}

# Function to check application status
check_status() {
    echo "Checking status of $APP_NAME service..."
    sudo systemctl status "$APP_NAME"
}

# Function to view application logs
view_logs() {
    echo "Displaying logs for $APP_NAME service..."
    echo "Press Ctrl+C to exit log view."
    sudo journalctl -u "$APP_NAME.service" -f
}

# Ensure service file exists
create_service_file

# Main menu loop
while true; do
    show_menu
    read -p "Enter your choice [1-6]: " choice

    case $choice in
        1) start_app ;;
        2) stop_app ;;
        3) restart_app ;;
        4) check_status ;;
        5) view_logs ;;
        6) echo "Exiting script."; exit 0 ;;
        *) echo "Invalid choice. Please enter a number between 1 and 6." ;;
    esac

    echo
done
