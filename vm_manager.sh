#!/bin/bash

CONFIG_FILE="vm_config.conf"

# Function to read saved configuration
read_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    echo "Reading configuration from $CONFIG_FILE..."
    source "$CONFIG_FILE"
  else
    echo "Configuration file not found. Defaults will be used, and user input is required."
  fi
}

# Function to save user-provided configuration
save_config() {
  echo "Saving configuration to $CONFIG_FILE..."
  cat <<EOF >"$CONFIG_FILE"
VM_NAME="$VM_NAME"
VM_MEMORY="$VM_MEMORY"
VM_CPUS="$VM_CPUS"
VM_DISK_SIZE="$VM_DISK_SIZE"
ISO_PATH="$ISO_PATH"
NUM_INTERFACES="$NUM_INTERFACES"
BRIDGE_INTERFACES=(${BRIDGE_INTERFACES[@]})
IP_ADDRESSES=(${IP_ADDRESSES[@]})
EOF
}

# Function to generate cloud-init ISO
generate_cloud_init_iso() {
  CLOUD_INIT_ISO="/var/lib/libvirt/images/${VM_NAME}-cloud-init.iso"
  CLOUD_INIT_DIR="/tmp/cloud-init-${VM_NAME}"
  mkdir -p "$CLOUD_INIT_DIR"

  # Create user-data
  cat <<EOF >"${CLOUD_INIT_DIR}/user-data"
#cloud-config
hostname: $VM_NAME
manage_etc_hosts: true
network:
  version: 2
  ethernets:
EOF

  for ((i = 0; i < NUM_INTERFACES; i++)); do
    IFACE_NAME="eth${i}"
    IP="${IP_ADDRESSES[i]}"
    if [[ -z "$IP" ]]; then
      CONFIG="      $IFACE_NAME:
        dhcp4: true"
    else
      CONFIG="      $IFACE_NAME:
        dhcp4: false
        addresses: [$IP/24]"
    fi
    echo "$CONFIG" >>"${CLOUD_INIT_DIR}/user-data"
  done

  # Create meta-data
  cat <<EOF >"${CLOUD_INIT_DIR}/meta-data"
instance-id: ${VM_NAME}
local-hostname: ${VM_NAME}
EOF

  # Generate ISO
  genisoimage -output "$CLOUD_INIT_ISO" -volid cidata -joliet -rock "${CLOUD_INIT_DIR}/user-data" "${CLOUD_INIT_DIR}/meta-data"
  rm -rf "$CLOUD_INIT_DIR"

  echo "$CLOUD_INIT_ISO"
}

# Function to create a new virtual machine
# Function to create a new virtual machine
create_vm() {
  read_config

  echo "Enter details to create a new virtual machine. Press Enter to use saved or default values (shown in brackets)."

  while true; do
    read -p "Enter the name of the virtual machine [${VM_NAME:-vm1}]: " USER_INPUT
    VM_NAME=${USER_INPUT:-${VM_NAME:-vm1}}

    # Check if the VM name already exists
    if virsh list --all | grep -qw "$VM_NAME"; then
      echo "Error: Guest name '$VM_NAME' is already in use. Please provide a different name."
    else
      break
    fi
  done

  read -p "Enter the amount of memory (in MB, e.g., 2048) [${VM_MEMORY:-2048}]: " USER_INPUT
  VM_MEMORY=${USER_INPUT:-${VM_MEMORY:-2048}}

  read -p "Enter the number of CPUs (e.g., 2) [${VM_CPUS:-2}]: " USER_INPUT
  VM_CPUS=${USER_INPUT:-${VM_CPUS:-2}}

  while true; do
    read -p "Enter the size of the disk (in GB, e.g., 20) [${VM_DISK_SIZE:-20}]: " USER_INPUT
    VM_DISK_SIZE=${USER_INPUT:-${VM_DISK_SIZE:-20}}
    if [[ "$VM_DISK_SIZE" =~ ^[0-9]+$ ]]; then
      break
    else
      echo "Invalid disk size. Please enter a numeric value."
    fi
  done

  # Disk path and ISO handling logic (unchanged)
  while true; do
  read -p "Enter the path to the ISO, IMG, or QCOW2 file [${ISO_PATH:-/var/lib/libvirt/images/default_image.img}]: " USER_INPUT
  ISO_PATH=${USER_INPUT:-${ISO_PATH:-/var/lib/libvirt/images/default_image.img}}

  # Normalize the file path
  ABSOLUTE_PATH=$(readlink -f "$ISO_PATH" 2>/dev/null || echo "$ISO_PATH")

  if [[ -f "$ABSOLUTE_PATH" && ( "$ABSOLUTE_PATH" =~ \.iso$ || "$ABSOLUTE_PATH" =~ \.img$ || "$ABSOLUTE_PATH" =~ \.qcow2$ ) ]]; then
    # Determine the extension
    EXTENSION="${ABSOLUTE_PATH##*.}"

    # Handle disk path based on the extension
    if [[ "$EXTENSION" == "qcow2" || "$EXTENSION" == "img" ]]; then
      # Default disk path
      DISK_PATH="/var/lib/libvirt/images/${VM_NAME}.${EXTENSION}"

      # Check if the disk is already in use
      VM_EXIST=$(virsh domblklist "$VM_NAME" 2>/dev/null | grep -w "$DISK_PATH")
      if [[ -n "$VM_EXIST" ]]; then
        echo "Error: Disk $DISK_PATH is already in use by the VM '$VM_NAME'."
        continue
      fi

      # Default to copying the image
      read -p "Do you want to copy the provided image for this VM (default: yes)? [yes/no]: " COPY_IMAGE
      COPY_IMAGE=${COPY_IMAGE:-yes}

      if [[ "$COPY_IMAGE" =~ ^[Yy][Ee][Ss]$ || "$COPY_IMAGE" =~ ^[Yy]$ ]]; then
        echo "Copying image to $DISK_PATH..."
        rsync --progress "$ABSOLUTE_PATH" "$DISK_PATH"
        if [[ $? -ne 0 ]]; then
          echo "Error copying the image. Please check the path and try again."
          exit 1
        fi
      else
        DISK_PATH="$ABSOLUTE_PATH"
      fi

    elif [[ "$EXTENSION" == "iso" ]]; then
      # Use ISO as the installation media and create a new disk
      DISK_PATH="/var/lib/libvirt/images/${VM_NAME}.qcow2"
      echo "Creating a new disk image for the VM at $DISK_PATH..."
      qemu-img create -f qcow2 "$DISK_PATH" "${VM_DISK_SIZE}G"
      if [[ $? -ne 0 ]]; then
        echo "Error creating the disk image. Please check the configuration and try again."
        exit 1
      fi
    else
      echo "Unsupported file format: $EXTENSION"
      exit 1
    fi
    break
  else
    echo "Error: File does not exist or is not an ISO/IMG/QCOW2 file. Please enter a valid path."
  fi
done


  # Network and cloud-init handling logic (unchanged)
  read -p "Enter the number of network interfaces to add [${NUM_INTERFACES:-1}]: " USER_INPUT
  NUM_INTERFACES=${USER_INPUT:-${NUM_INTERFACES:-1}}

  BRIDGE_INTERFACES=()
  IP_ADDRESSES=()
  for ((i = 1; i <= NUM_INTERFACES; i++)); do
    read -p "Enter the name of the bridge interface for network interface $i (e.g., br0) [${BRIDGE_INTERFACES[i-1]:-br0}]: " USER_INPUT
    BRIDGE_INTERFACE=${USER_INPUT:-${BRIDGE_INTERFACES[i-1]:-br0}}
    while [[ ! $(ip link show "$BRIDGE_INTERFACE" 2>/dev/null) ]]; do
      echo "Error: Bridge interface '$BRIDGE_INTERFACE' does not exist!"
      read -p "Enter a valid bridge interface for network interface $i: " BRIDGE_INTERFACE
    done
    BRIDGE_INTERFACES+=("$BRIDGE_INTERFACE")

    read -p "Enter the IP address for network interface $i (leave blank for DHCP): " IP_ADDRESS
    IP_ADDRESSES+=("$IP_ADDRESS")
  done

  save_config

  CLOUD_INIT_ISO=$(generate_cloud_init_iso)

  NETWORK_OPTIONS=()
  for BRIDGE in "${BRIDGE_INTERFACES[@]}"; do
    NETWORK_OPTIONS+=("--network" "bridge=$BRIDGE")
  done

  echo "Creating virtual machine '$VM_NAME'..."
  virt-install \
    --name="$VM_NAME" \
    --memory="$VM_MEMORY" \
    --vcpus="$VM_CPUS" \
    --disk path="$DISK_PATH",format=qcow2 \
    --disk path="$CLOUD_INIT_ISO",device=cdrom \
    --cdrom="$ISO_PATH" \
    "${NETWORK_OPTIONS[@]}" \
    --os-type=linux \
    --os-variant=generic \
    --graphics vnc,listen=0.0.0.0 \
    --noautoconsole

  if [[ $? -ne 0 ]]; then
    echo "Failed to create virtual machine '$VM_NAME'."
    return 1
  fi

  echo "Virtual machine '$VM_NAME' created successfully."
}


# Function to delete a virtual machine
delete_vm() {
  read -p "Enter the name of the virtual machine to delete: " VM_NAME
  virsh destroy "$VM_NAME" 2>/dev/null
  virsh undefine "$VM_NAME" --remove-all-storage
  echo "Virtual machine '$VM_NAME' deleted successfully."
}

# Main Menu
while true; do
  echo "Choose an action:"
  echo "1) List all virtual machines"
  echo "2) Start a virtual machine"
  echo "3) Check the state of a virtual machine"
  echo "4) Create a new virtual machine"
  echo "5) Delete a virtual machine"
  echo "6) Exit"
  read -p "Enter your choice (1-6): " CHOICE

  case "$CHOICE" in
    1)
      echo "Available Virtual Machines:"
      virsh list --all
      ;;
    2)
      read -p "Enter the name of the virtual machine to start: " VM_NAME
      virsh start "$VM_NAME"
      ;;
    3)
      read -p "Enter the name of the virtual machine to check: " VM_NAME
      virsh domstate "$VM_NAME"
      ;;
    4)
      create_vm
      ;;
    5)
      delete_vm
      ;;
    6)
      echo "Exiting."
      exit 0
      ;;
    *)
      echo "Invalid choice. Please try again."
      ;;
  esac
done
root@jvision-lnx109:~# 