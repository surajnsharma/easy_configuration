#!/bin/bash

# Define the parameter file
PARAM_FILE="./vlan_config.conf"

# Function to read parameters from file or prompt user
get_parameters() {
  if [[ -f "$PARAM_FILE" ]]; then
    echo "Reading configuration from $PARAM_FILE..."
    source "$PARAM_FILE"
  else
    echo "Configuration file not found. Please provide input."
    prompt_user_for_parameters
  fi
}

# Function to prompt user for parameters
prompt_user_for_parameters() {
  read -p "Enter the parent interface (default: ${PARENT_IF:-eno12409np1}): " NEW_PARENT_IF
  read -p "Enter the starting VLAN ID (default: ${VLAN_START:-10}): " NEW_VLAN_START
  read -p "Enter the ending VLAN ID (default: ${VLAN_END:-20}): " NEW_VLAN_END

  # Use defaults if inputs are empty
  PARENT_IF=${NEW_PARENT_IF:-$PARENT_IF}
  VLAN_START=${NEW_VLAN_START:-$VLAN_START}
  VLAN_END=${NEW_VLAN_END:-$VLAN_END}

  # Validate inputs
  if ! ip link show "$PARENT_IF" &>/dev/null; then
    echo "Error: Parent interface $PARENT_IF does not exist!"
    exit 1
  fi

  if [[ ! $VLAN_START =~ ^[0-9]+$ ]] || [[ ! $VLAN_END =~ ^[0-9]+$ ]] || [[ $VLAN_START -gt $VLAN_END ]]; then
    echo "Error: Invalid VLAN range!"
    exit 1
  fi

  # Save parameters to file
  echo "Saving configuration to $PARAM_FILE..."
  echo "PARENT_IF=$PARENT_IF" > "$PARAM_FILE"
  echo "VLAN_START=$VLAN_START" >> "$PARAM_FILE"
  echo "VLAN_END=$VLAN_END" >> "$PARAM_FILE"
}


# Function to ensure the physical interface is up
ensure_physical_interface_up() {
  if [[ "$(ip -br link show "$PARENT_IF" | awk '{print $2}')" != "UP" ]]; then
    echo "Bringing up parent interface $PARENT_IF..."
    sudo ip link set dev "$PARENT_IF" up
  else
    echo "Parent interface $PARENT_IF is already up."
  fi
}

# Function to add VLANs
add_vlans() {
  if [[ -f "$PARAM_FILE" ]]; then
    echo "Saved configuration found:"
    source "$PARAM_FILE"
    echo "Parent Interface: $PARENT_IF"
    echo "VLAN Range: $VLAN_START-$VLAN_END"
    read -p "Use these values? (yes/no): " USE_SAVED
    if [[ "$USE_SAVED" != "yes" ]]; then
      echo "Provide new values:"
      prompt_user_for_parameters
    fi
  else
    prompt_user_for_parameters
  fi

  # Ensure physical interface is up
  ensure_physical_interface_up

  for VLAN_ID in $(seq $VLAN_START $VLAN_END); do
    VLAN_IF="${PARENT_IF}.${VLAN_ID}"
    BRIDGE_IF="br${VLAN_ID}"

    echo "Processing VLAN ID: ${VLAN_ID}"

    # Check if VLAN interface already exists
    if ip link show "$VLAN_IF" &>/dev/null; then
      echo "VLAN interface $VLAN_IF already exists. Skipping creation."
    else
      echo "Creating VLAN interface $VLAN_IF on $PARENT_IF..."
      sudo ip link add link "$PARENT_IF" name "$VLAN_IF" type vlan id "$VLAN_ID"
      sudo ip link set dev "$VLAN_IF" up
    fi

    # Check if bridge already exists
    if ip link show "$BRIDGE_IF" &>/dev/null; then
      echo "Bridge $BRIDGE_IF already exists. Skipping creation."
    else
      echo "Creating bridge $BRIDGE_IF..."
      sudo ip link add name "$BRIDGE_IF" type bridge
      sudo ip link set dev "$BRIDGE_IF" up
    fi

    # Attach VLAN interface to the bridge
    if bridge link show | grep -q "$VLAN_IF"; then
      echo "VLAN interface $VLAN_IF is already attached to $BRIDGE_IF."
    else
      echo "Attaching $VLAN_IF to bridge $BRIDGE_IF..."
      sudo ip link set dev "$VLAN_IF" master "$BRIDGE_IF"
    fi

    echo "Configuration for VLAN ID $VLAN_ID completed."
    echo "-------------------------------------------"
  done

  echo "VLAN and bridge setup completed for VLANs ${VLAN_START}-${VLAN_END}."
}

# Function to delete VLANs
delete_vlans() {
  get_parameters

  echo "Choose deletion type:"
  echo "1) Delete all VLANs in the range ${VLAN_START}-${VLAN_END} (default)"
  echo "2) Delete specific VLAN(s)"
  read -p "Enter your choice (1 or 2, default 1): " DELETE_TYPE

  DELETE_TYPE=${DELETE_TYPE:-1} # Default to option 1 if no input

  if [[ "$DELETE_TYPE" == "1" ]]; then
    echo "Deleting all VLANs in the range ${VLAN_START}-${VLAN_END}..."
    for VLAN_ID in $(seq $VLAN_START $VLAN_END); do
      delete_vlan "$VLAN_ID"
    done
  elif [[ "$DELETE_TYPE" == "2" ]]; then
    read -p "Enter specific VLAN IDs to delete (comma-separated): " VLAN_LIST
    if [[ -z "$VLAN_LIST" ]]; then
      echo "No VLANs specified. Exiting."
      exit 1
    fi
    IFS=',' read -ra VLAN_ARRAY <<< "$VLAN_LIST"
    for VLAN_ID in "${VLAN_ARRAY[@]}"; do
      delete_vlan "$VLAN_ID"
    done
  else
    echo "Invalid choice! Exiting."
    exit 1
  fi
}

# Function to delete a single VLAN
delete_vlan() {
  VLAN_ID=$1
  VLAN_IF="${PARENT_IF}.${VLAN_ID}"
  BRIDGE_IF="br${VLAN_ID}"

  echo "Processing VLAN ID: ${VLAN_ID}"

  # Check and delete the VLAN interface
  if ip link show "$VLAN_IF" &>/dev/null; then
    echo "Deleting VLAN interface $VLAN_IF..."
    sudo ip link set dev "$VLAN_IF" down
    sudo ip link delete "$VLAN_IF" type vlan
  else
    echo "VLAN interface $VLAN_IF does not exist. Skipping."
  fi

  # Check and delete the bridge
  if ip link show "$BRIDGE_IF" &>/dev/null; then
    echo "Deleting bridge $BRIDGE_IF..."
    sudo ip link set dev "$BRIDGE_IF" down
    sudo ip link delete "$BRIDGE_IF" type bridge
  else
    echo "Bridge $BRIDGE_IF does not exist. Skipping."
  fi

  echo "Cleanup for VLAN ID $VLAN_ID completed."
  echo "-------------------------------------"
}

# Function to show VLAN-to-Bridge Mapping
show_vlan_mapping() {
  get_parameters

  echo "VLAN-to-Bridge Mapping:"
  echo "-------------------------------------"
  for VLAN_ID in $(seq $VLAN_START $VLAN_END); do
    VLAN_IF="${PARENT_IF}.${VLAN_ID}"
    BRIDGE_IF="br${VLAN_ID}"

    # Get VLAN interface state
    if ip link show "$VLAN_IF" &>/dev/null; then
      VLAN_STATE=$(ip -br link show "$VLAN_IF" | awk '{print $2}') # UP/DOWN
    else
      VLAN_STATE="NOT FOUND"
    fi

    # Get bridge state
    if ip link show "$BRIDGE_IF" &>/dev/null; then
      BRIDGE_STATE="UP"
    else
      BRIDGE_STATE="NOT FOUND"
    fi

    # Display mapping
    echo "VLAN $VLAN_ID ($VLAN_IF) -> Bridge: $BRIDGE_IF [$VLAN_STATE/$BRIDGE_STATE]"
  done
  echo "-------------------------------------"
}

# Main Menu
echo "Choose an action:"
echo "1) Add VLANs"
echo "2) Delete VLANs"
echo "3) Show VLAN-to-Bridge Mapping"
read -p "Enter your choice (1, 2, or 3): " ACTION

case "$ACTION" in
  1)
    add_vlans
    ;;
  2)
    delete_vlans
    ;;
  3)
    show_vlan_mapping
    ;;
  *)
    echo "Invalid choice! Exiting."
    exit 1
    ;;
esac

