import logging
import time
import yaml
from concurrent.futures import ThreadPoolExecutor
from jnpr.junos import Device
from jnpr.junos.exception import ConnectError, RpcError

# Configure global logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler('chassis_alarms.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.ERROR)  # Only print errors to console
console_handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(console_handler)

# Suppress verbose logs from underlying libraries
logging.getLogger("ncclient.transport.ssh").setLevel(logging.WARNING)
logging.getLogger("paramiko.transport").setLevel(logging.WARNING)


def load_devices(file_path):
    """Load device details and global credentials from a YAML file."""
    try:
        with open(file_path, 'r') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        logging.error(f"Device file '{file_path}' not found.")
        print(f"Device file '{file_path}' not found.")
        return None
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML file '{file_path}': {e}")
        print(f"Error parsing YAML file '{file_path}': {e}")
        return None


def load_rpc_commands(file_path):
    """Load RPC commands from a text file."""
    try:
        with open(file_path, 'r') as file:
            commands = file.readlines()
            return [command.strip() for command in commands if command.strip()]
    except FileNotFoundError:
        logging.error(f"RPC command file '{file_path}' not found.")
        return []
    except Exception as e:
        logging.error(f"Error loading RPC commands from file '{file_path}': {e}")
        return []


def load_alarms(file_path):
    """Load the list of alarms to monitor from a text file."""
    try:
        with open(file_path, 'r') as file:
            alarms = file.readlines()
            return [' '.join(alarm.lower().split()) for alarm in alarms if alarm.strip()]  # Normalize for case/whitespace
    except FileNotFoundError:
        logging.error(f"Alarm file '{file_path}' not found.")
        print(f"Alarm file '{file_path}' not found.")
        return []
    except Exception as e:
        logging.error(f"Error loading alarms from file '{file_path}': {e}")
        print(f"Error loading alarms from file '{file_path}': {e}")
        return []


def execute_corrective_command(device, port, rpc_commands, alarm_text, retries=3):
    """
    Execute a corrective command for a specific port using RPC commands from a file.
    Retry up to three times if the specific alarm persists after command execution.
    """
    attempt = 0
    while attempt < retries:
        attempt += 1
        try:
            port_number = port.split("/")[-1]  # Extract the last number as the port number
            for command in rpc_commands:
                corrected_command = command.replace('port 1', f'port {port_number}')
                print(f"Executing command for port-{port}: {corrected_command} (Attempt {attempt})")
                logging.info(f"Executing command for port-{port} on {device.facts['hostname']}: {corrected_command}")
                device.rpc.cli(command=corrected_command)
                print(f"Command executed successfully for port-{port}: {corrected_command}")
                logging.info(f"Command executed successfully for port-{port}: {corrected_command}")
                time.sleep(1)

            # Wait before re-checking the alarm status
            time.sleep(3)

            # Verify if the specific alarm persists
            if not specific_alarm_still_exists(device, port, alarm_text):
                print(f"Alarm cleared for port-{port}: {alarm_text}")
                logging.info(f"Alarm cleared for port-{port}: {alarm_text}")
                return
            else:
                print(f"Alarm still exists for port-{port}: {alarm_text}. Retrying... (Attempt {attempt}/{retries})")
                logging.warning(f"Alarm still exists for port-{port}: {alarm_text}. Retrying... (Attempt {attempt}/{retries})")
        except RpcError as e:
            logging.error(f"Failed to execute corrective command for port-{port}: {e}")
            print(f"Failed to execute corrective command for port-{port}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error executing command for port-{port}: {e}")
            print(f"Unexpected error for port-{port}: {e}")

    print(f"Alarm persists for port-{port}: {alarm_text} after {retries} attempts. Moving on.")
    logging.error(f"Alarm persists for port-{port}: {alarm_text} after {retries} attempts. Moving on.")


def specific_alarm_still_exists(device, port, alarm_text):
    """Check if the specific alarm still exists for the port on the device."""
    try:
        alarms = device.rpc.get_alarm_information()
        alarms_list = alarms.xpath('.//alarm-description')
        for alarm in alarms_list:
            current_alarm_text = alarm.text.strip().lower() if alarm.text else ""
            if port in current_alarm_text and alarm_text in current_alarm_text:
                return True
        return False
    except Exception as e:
        logging.error(f"Error checking specific alarm for port-{port}: {e}")
        return False


def check_alarms(device, username, password, rpc_commands, alarm_list):
    """Connect to a device and check for chassis alarms."""
    try:
        print(f"Connecting to device {device['host']}...")
        logging.info(f"Connecting to device {device['host']} with a 3-second timeout...")
        with Device(host=device['host'], user=username, passwd=password, timeout=3) as dev:
            print(f"Connected to {device['host']}.")
            logging.info(f"Connected to {device['host']}.")

            alarms = dev.rpc.get_alarm_information()
            alarms_list = alarms.xpath('.//alarm-description')

            if not alarms_list:
                print(f"No alarms detected on {device['host']}.")
                logging.info(f"No chassis alarms detected on {device['host']}.")
                return

            print(f"Chassis alarms detected on {device['host']}:")
            logging.warning(f"Chassis alarms detected on {device['host']}:")
            handled_ports = set()

            for alarm in alarms_list:
                alarm_text = alarm.text.strip().lower() if alarm.text else ""
                if not alarm_text:
                    logging.warning("Incomplete alarm data detected. Skipping alarm.")
                    continue

                alarm_description = extract_alarm_description(alarm_text)

                if not any(all(word in alarm_description for word in pattern.split()) for pattern in alarm_list):
                    print(f"Ignored alarm: {alarm_text}")
                    logging.info(f"Ignored alarm: {alarm_text}")
                    continue

                print(f"Alarm found: {alarm_text}")
                logging.warning(f"Alarm matched: {alarm_text}")
                port = extract_port_from_alarm(alarm_text)

                if port and port not in handled_ports:
                    handled_ports.add(port)
                    execute_corrective_command(dev, port, rpc_commands, alarm_text)
                time.sleep(2)

    except ConnectError as e:
        logging.error(f"Connection failed for {device['host']}: {e}")
        print(f"Error: Unable to connect to {device['host']}. Skipping device.")
    except RpcError as e:
        logging.error(f"RPC error on device {device['host']}: {e}")
        print(f"Error: RPC error on {device['host']}. Skipping device.")
    except Exception as e:
        logging.error(f"Unexpected error on device {device['host']}: {e}")
        print(f"Unexpected error on {device['host']}: {e}")


def extract_alarm_description(alarm_text):
    """Extract the description of an alarm, ignoring the port number."""
    import re
    try:
        match = re.search(r':\s*(.*)', alarm_text)
        if match:
            return match.group(1).lower().strip()
        return alarm_text.lower().strip()
    except Exception as e:
        logging.error(f"Error extracting alarm description: {e}")
        return alarm_text.lower().strip()


def extract_port_from_alarm(alarm_text):
    """Extract port information from an alarm description."""
    import re
    try:
        match = re.search(r'port-(\d+/\d+/\d+)', alarm_text)
        if match:
            return match.group(1)
        logging.warning(f"No port information found in alarm: {alarm_text}")
    except Exception as e:
        logging.error(f"Error extracting port from alarm: {e}")
    return None


def process_device(device, username, password, rpc_commands, alarm_list):
    """Process a single device for alarms."""
    check_alarms(device, username, password, rpc_commands, alarm_list)


def main():
    devices_file = 'creds.yaml'
    rpc_file = 'rpc.text'
    alarm_file = 'alarm.text'

    config = load_devices(devices_file)
    rpc_commands = load_rpc_commands(rpc_file)
    alarm_list = load_alarms(alarm_file)

    if not config or not rpc_commands or not alarm_list:
        logging.error("Failed to load device configuration, RPC commands, or alarms. Exiting.")
        print("Failed to load device configuration, RPC commands, or alarms. Exiting.")
        return

    global_creds = config.get('global', {})
    devices = config.get('devices', [])

    with ThreadPoolExecutor() as executor:
        for device in devices:
            username = global_creds.get("username")
            password = global_creds.get("password")
            executor.submit(process_device, device, username, password, rpc_commands, alarm_list)


if __name__ == "__main__":
    main()
