import yaml
import json
import logging
import importlib
from collections import deque
from xml.sax.saxutils import escape
import time
from intent_functions import connect_to_device


# Custom XML Formatter for Logging
class XMLFormatter(logging.Formatter):
    def format(self, record):
        message = escape(record.getMessage())
        log_entry = (
            f"<log>\n"
            f"  <time>{self.formatTime(record)}</time>\n"
            f"  <level>{record.levelname}</level>\n"
            f"  <message>{message}</message>\n"
            f"</log>\n"
        )
        return log_entry


# Configure Logging
xml_handler = logging.FileHandler("debug.xml", mode="w")
xml_formatter = XMLFormatter()
xml_handler.setFormatter(xml_formatter)

logging.basicConfig(
    level=logging.DEBUG,
    handlers=[xml_handler]
)


# Load JSON and YAML Files
def load_json(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing JSON file {file_path}: {e}")
        return None


def load_yaml(file_path):
    try:
        with open(file_path, 'r') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML file {file_path}: {e}")
        return None


def get_device_credentials(device, global_creds):
    """
    Retrieve device-specific credentials or fallback to global credentials.
    """
    username = device.get("username", global_creds.get("username"))
    password = device.get("password", global_creds.get("password"))

    if not username or not password:
        logging.error(f"Device '{device.get('name')}' is missing valid credentials.")
        return None, None

    return username, password


# Execute a Single Intent
def execute_intent(device, intent_details, function_name, global_creds):
    """
    Executes a specific intent on a resolved device using the provided function.
    """
    parameters = intent_details.get("parameters", {})
    username, password = get_device_credentials(device, global_creds)
    if not username or not password:
        return False

    try:
        intent_module = importlib.import_module("intent_functions")
        function = getattr(intent_module, function_name)
        return function(device, username=username, password=password, **parameters)
    except AttributeError:
        logging.error(f"Function '{function_name}' not found in intent_functions.py.")
        return False
    except Exception as e:
        logging.error(f"Error executing function '{function_name}' on device '{device['name']}': {e}")
        return False


def resolve_devices_for_intent(intent_name, creds_file, intents_registry):
    """
    Resolves devices for an intent based on explicitly defined devices or tags.
    """
    creds = load_yaml(creds_file)

    if not intents_registry or not creds:
        logging.error(f"Failed to load required files for resolving intent '{intent_name}'.")
        return []

    intent_details = intents_registry.get("intents", {}).get(intent_name, {})
    intent_tags = intent_details.get("tags", [])
    intent_devices = intent_details.get("devices", [])

    resolved_devices = []

    # Step 1: Resolve explicitly listed devices
    if intent_devices:
        resolved_devices = [
            device for device in creds["devices"]
            if device["name"] in intent_devices
        ]
        logging.info(
            f"Intent '{intent_name}' resolved explicitly by devices: {[d['name'] for d in resolved_devices]}"
        )

    # Step 2: Resolve devices by tags, ensuring no duplicates
    if intent_tags:
        tagged_devices = [
            device for device in creds["devices"]
            if any(tag in device.get("tags", []) for tag in intent_tags)
        ]
        for device in tagged_devices:
            if device not in resolved_devices:
                resolved_devices.append(device)
        logging.info(
            f"Intent '{intent_name}' resolved by tags: {[d['name'] for d in tagged_devices]}"
        )

    if not resolved_devices:
        logging.warning(
            f"No devices resolved for intent '{intent_name}'. "
            f"Required tags: {intent_tags}, Explicit devices: {intent_devices}"
        )

    return resolved_devices


def execute_intents_round_robin(device_name, sequence, intents_registry, creds_file, global_creds):
    """
    Executes intents for a single device in round-robin fashion, enforcing tag and device matching logic.
    """
    queue = deque(sequence)
    intents = intents_registry.get("intents", {})

    creds = load_yaml(creds_file)
    device = next((d for d in creds["devices"] if d["name"] == device_name), None)

    if not device:
        logging.error(f"Device '{device_name}' not found in device credentials.")
        return

    logging.info(f"Processing device '{device_name}' with tags: {device.get('tags', [])}")
    print(f"\nProcessing intents for device: {device_name}", flush=True)

    # Track remaining iterations for each intent
    iterations_remaining = {item["intent"]: item.get("iterations", 1) for item in sequence}

    # Process intents until all iterations are complete
    while any(iterations_remaining[intent] > 0 for intent in iterations_remaining):
        if not queue:
            logging.warning(f"Queue is empty for device '{device_name}'. Exiting.")
            break

        current_item = queue.popleft()
        intent_name = current_item["intent"]
        sleep_timer = current_item.get("sleep_timer", 0)

        # Skip intents with no remaining iterations
        if iterations_remaining[intent_name] <= 0:
            continue

        # Resolve intent details
        intent_details = intents.get(intent_name)
        if not intent_details:
            logging.warning(f"Intent '{intent_name}' not found in intents_registry.json.")
            continue

        description = intent_details.get("description", "No description provided")
        print(f"Executing intent '{intent_name}' on device '{device_name}': {description}", flush=True)
        logging.info(
            f"Executing intent '{intent_name}' for device '{device_name}'. "
            f"Description: {description}. Remaining iterations: {iterations_remaining[intent_name]}"
        )

        # Execute the intent
        success = execute_intent(device, intent_details, intent_details.get("function"), global_creds)

        if success:
            iterations_remaining[intent_name] -= 1
            logging.info(
                f"Intent '{intent_name}' executed successfully on device '{device_name}'. "
                f"Remaining iterations: {iterations_remaining[intent_name]}"
            )

            # Add a sleep timer between iterations
            if iterations_remaining[intent_name] > 0 and sleep_timer > 0:
                print(f"Pausing for {sleep_timer} seconds before next iteration of intent '{intent_name}'...", flush=True)
                logging.info(f"Sleeping for {sleep_timer} seconds between iterations for intent '{intent_name}'.")
                time.sleep(sleep_timer)

        # Only re-add the intent to the queue if there are remaining iterations
        if iterations_remaining[intent_name] > 0:
            queue.append(current_item)

def execute_all_intents(intents_file, creds_file):
    intents_registry = load_json(intents_file)
    creds = load_yaml(creds_file)

    if not intents_registry or not creds:
        logging.error("Failed to load required files.")
        return

    intent_sequence = intents_registry.get("intent_sequence", {})
    global_creds = creds.get("global", {})  # Extract global credentials
    all_devices = [device["name"] for device in creds.get("devices", [])]

    for device_name, sequence in intent_sequence.items():
        # Check if the device exists in the device credentials
        if device_name not in all_devices:
            print(f"Warning: Device '{device_name}' not found in device_creds.yaml. Skipping.", flush=True)
            logging.warning(f"Device '{device_name}' listed in intent_sequence but not found in device_creds.yaml. Skipping.")
            continue

        print(f"\nProcessing intents for device: {device_name}", flush=True)
        logging.info(f"Processing intents for device: {device_name}")
        for sequence_item in sequence:
            intent_name = sequence_item["intent"]
            intent_details = intents_registry.get("intents", {}).get(intent_name, {})
            description = intent_details.get("description", "No description provided")
            print(f"- Intent '{intent_name}': {description}", flush=True)
            logging.info(f"Intent '{intent_name}' description: {description}")
        execute_intents_round_robin(device_name, sequence, intents_registry, creds_file, global_creds)

# Main Script
if __name__ == "__main__":
    intents_file = "intents_registry.json"
    creds_file = "device_creds.yaml"
    execute_all_intents(intents_file, creds_file)
