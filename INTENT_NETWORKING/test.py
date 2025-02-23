#test.py#
import yaml
import json
import logging
import importlib
import time, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from intent_functions import connect_to_device


# Logging setup
logging.basicConfig(
    level=logging.DEBUG,
    filename="debug.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s"
)

console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter("%(message)s")
console.setFormatter(formatter)
logging.getLogger().addHandler(console)
logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("ncclient").setLevel(logging.WARNING)


# Utility Functions
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


def get_device_credentials(device_info, global_creds):
    username = device_info.get("username", global_creds.get("username"))
    password = device_info.get("password", global_creds.get("password"))
    if not username or not password:
        logging.error(f"Device '{device_info.get('name', 'unknown')}' is missing valid credentials.")
        return None, None
    return username, password





# Intent Execution

def validate_intents(intents_registry, intent_sequence, creds):
    """
    Validates intents in device_intent.yaml against intents_registry.json and ensures
    that the metadata matches device properties.
    """
    registered_intents = intents_registry.get("intents", {})
    devices = creds.get("devices", [])
    errors = []

    for device_name, intents in intent_sequence.items():
        # Find the device details
        device_info = next((d for d in devices if d["name"] == device_name), None)
        if not device_info:
            errors.append(f"Device '{device_name}' is not defined in device_creds.yaml.")
            continue
        device_tags = device_info.get("tags", [])
        device_type = device_info.get("type", "")
        for intent in intents:
            intent_name = intent["intent"]
            active = intent.get("active", "yes").strip().lower()

            # Skip validation for inactive intents
            if active == "no":
                logging.info(f"Skipping validation for inactive intent '{intent_name}' on device '{device_name}'.")
                continue

            # Validate intent exists in intents_registry.json
            registered_intent = registered_intents.get(intent_name)
            if not registered_intent:
                errors.append(f"Intent '{intent_name}' is not registered in intents_registry.json.")
                continue

            # Check device metadata against the intent
            allowed_devices = registered_intent.get("devices", [])
            allowed_tags = registered_intent.get("tags", [])
            allowed_types = registered_intent.get("supported_device_types", [])

            is_device_allowed = not allowed_devices or device_name in allowed_devices
            is_tag_allowed = not allowed_tags or any(tag in device_tags for tag in allowed_tags)
            is_type_allowed = not allowed_types or device_type in allowed_types

            if not (is_device_allowed or is_tag_allowed or is_type_allowed):
                errors.append(f"Intent '{intent_name}' does not match metadata for device '{device_name}'.")

    if errors:
        for error in errors:
            logging.error(error)
        raise ValueError("Validation failed. Check logs for details.")


def extract_snapshot_metrics(snapshot_file):
    """
    Extracts metrics like the number of BGP sessions up and interfaces up from the snapshot file.
    """
    bgp_sessions_up = 0
    interfaces_up = 0

    try:
        with open(snapshot_file, 'r') as file:
            content = file.read()

        # Parse BGP sessions
        if "BGP Summary:" in content:
            bgp_section = content.split("BGP Summary:")[1].split("Interfaces Terse:")[0]
            bgp_sessions_up = bgp_section.count("Established")

        # Parse Interfaces
        if "Interfaces Terse:" in content:
            interface_section = content.split("Interfaces Terse:")[1]
            interfaces_up = interface_section.count("up")

    except Exception as e:
        logging.error(f"Error extracting metrics from snapshot: {e}")

    return {"bgp_sessions_up": bgp_sessions_up, "interfaces_up": interfaces_up}


def execute_intents_round_robin_for_device(device_name, intents_registry, intent_sequence, creds, global_creds):

    device_info = next((d for d in creds["devices"] if d["name"] == device_name), None)
    if not device_info:
        logging.error(f"Device '{device_name}' not found in device credentials.")
        return {device_name: {"status": "failed", "details": []}}

    sequence = intent_sequence.get(device_name, [])
    if not sequence:
        logging.info(f"No intents defined for device '{device_name}'.")
        return {device_name: {"status": "skipped", "details": []}}

    max_iterations = max(intent.get("iterations", 1) for intent in sequence)
    summary = {"status": "completed", "details": []}
    logging.info(f"Starting round-robin execution for device '{device_name}' with {max_iterations} global iterations.")

    for iteration in range(max_iterations):
        logging.info(f"Starting Global Iteration {iteration + 1}/{max_iterations} for device '{device_name}'.")

        for intent in sequence:
            intent_name = intent["intent"]
            intent_iterations = intent.get("iterations", 1)
            sleep_timer = intent.get("sleep_timer", 0)
            parameters = intent.get("parameters", {})
            active = intent.get("active", "yes").strip().lower()

            if active != "yes" or iteration >= intent_iterations:
                logging.info(f"Skipping intent '{intent_name}' for device '{device_name}' during iteration {iteration + 1}.")
                continue

            intent_details = intents_registry.get("intents", {}).get(intent_name, {})
            function_name = intent_details.get("function")
            logging.info(f"Executing intent '{intent_name}' for device '{device_name}' - Iteration {iteration + 1}/{intent_iterations}.")

            try:
                result = execute_intent(device_info, intent_details, function_name, global_creds, parameters)
                iteration_status = result.get("summary", {}).get("status", "fail")

                intent_summary = next((s for s in summary["details"] if s["intent"] == intent_name), None)
                if not intent_summary:
                    intent_summary = {"intent": intent_name, "iterations": [], "status": "success"}
                    summary["details"].append(intent_summary)

                intent_summary["iterations"].append({"iteration": iteration + 1, "status": iteration_status})
                if iteration_status != "success":
                    intent_summary["status"] = "failed"
                    summary["status"] = "failed"

            except Exception as e:
                logging.error(f"Error executing intent '{intent_name}' on device '{device_name}': {e}")
                intent_summary = next((s for s in summary["details"] if s["intent"] == intent_name), None)
                if not intent_summary:
                    intent_summary = {"intent": intent_name, "iterations": [], "status": "success"}
                    summary["details"].append(intent_summary)
                intent_summary["iterations"].append({"iteration": iteration + 1, "status": "fail"})
                intent_summary["status"] = "failed"
                summary["status"] = "failed"

            if iteration < intent_iterations - 1:
                logging.info(f"Sleeping for {sleep_timer} seconds before the next intent.")
                time.sleep(sleep_timer)

    logging.info(f"Completed round-robin execution for device '{device_name}'.")
    return {device_name: summary}

def execute_all_intents_round_robin(intents_registry_file, device_intent_file, creds_file):
    """
    Executes all intents for all devices in a round-robin fashion:
    - Iteration 1 of all intents for all devices is executed first.
    - Then Iteration 2, and so on.
    """
    intents_registry = load_json(intents_registry_file)
    intent_sequences = load_yaml(device_intent_file)
    creds = load_yaml(creds_file)

    if not intents_registry or not intent_sequences or not creds:
        logging.error("Failed to load required files.")
        return

    intent_sequence = intent_sequences.get("intent_sequence", {})
    global_creds = creds.get("global", {})
    summary = {}

    with ThreadPoolExecutor() as executor:
        future_to_device = {
            executor.submit(
                execute_intents_round_robin_for_device,
                device_name,
                intents_registry,
                intent_sequence,
                creds,
                global_creds
            ): device_name for device_name in intent_sequence.keys()
        }

        for future in as_completed(future_to_device):
            device_name = future_to_device[future]
            try:
                result = future.result()
                summary.update(result)
            except Exception as e:
                logging.error(f"Error processing intents for device '{device_name}': {e}")
                summary[device_name] = {"status": "failed"}

    # Final Summary
    logging.info("\nFinal Summary:\n")
    for device, result in summary.items():
        logging.info(f"Device: {device}")
        logging.info(f"  Status: {result['status']}")
        for intent in result["details"]:
            pass_count = sum(1 for iteration in intent["iterations"] if iteration["status"] == "success")
            fail_count = sum(1 for iteration in intent["iterations"] if iteration["status"] != "success")
            total_iterations = len(intent["iterations"])
            logging.info(f"  - Intent: {intent['intent']}")
            logging.info(f"    Status: Pass: {pass_count} Iterations, Fail: {fail_count} Iterations")
            logging.info(f"    Total Iterations: {total_iterations}")

    return summary

'''def execute_intent(device_info, intent_details, function_name, global_creds, device_parameters):
    """
    Execute a specific intent for a given device.
    """
    # Merge parameters and remove duplicate keys
    parameters = {**intent_details.get("parameters", {}), **device_parameters}
    parameters.pop("device_name", None)

    # Fetch device credentials
    username, password = get_device_credentials(device_info, global_creds)
    if not username or not password:
        logging.error(f"Device '{device_info.get('name')}' missing credentials.")
        return {"summary": {"status": "fail", "error": "Missing credentials"}, "snapshot_status": {}, "metrics": {}}

    try:
        # Connect to the device
        dev = connect_to_device(device_info["host"], username, password)
        if not dev or not dev.connected:
            logging.error(f"Failed to connect to device '{device_info['name']}'.")
            return {"summary": {"status": "fail", "error": "Connection failed"}, "snapshot_status": {}, "metrics": {}}

        # Dynamically load the intent function
        intent_module = importlib.import_module("intent_functions")
        function = getattr(intent_module, function_name, None)
        if not function:
            logging.error(f"Intent function '{function_name}' not found in intent_functions.")
            return {"summary": {"status": "fail", "error": "Function not found"}, "snapshot_status": {}, "metrics": {}}

        # Handle special logic for specific intents
        if function_name == "compare_pre_post_event_states":
            hostname = dev.hostname
            pre_event_file = f"./snapshots/pre/{hostname}_pre.xml"
            post_event_file = f"./snapshots/post/{hostname}_post.xml"

            # Validate file existence
            missing_files = [f for f in [pre_event_file, post_event_file] if not os.path.exists(f)]
            if missing_files:
                error_message = f"File(s) not found: {', '.join(missing_files)}"
                logging.error(error_message)
                return {
                    "summary": {"status": "fail", "error": error_message},
                    "snapshot_status": {},
                    "metrics": {},
                }

            # Compare files
            try:
                logging.info(
                    f"Comparing state between pre-event file: {pre_event_file} and post-event file: {post_event_file}.")
                result = function(pre_event_file=pre_event_file, post_event_file=post_event_file)
                if isinstance(result, dict):
                    diff_file = result.get("diff_file", None)
                    return {
                        "summary": {"status": "success" if result["status"] == "pass" else "fail"},
                        "snapshot_status": {},
                        "metrics": result.get("diff", {}),
                        "diff_file": diff_file,
                    }
                else:
                    logging.error(f"Unexpected result format from compare_pre_post_event_states: {result}")
                    return {"summary": {"status": "fail", "error": "Unexpected result format"}}
            except Exception as e:
                error_message = f"Error during state comparison: {e}"
                logging.error(error_message)
                return {
                    "summary": {"status": "fail", "error": error_message},
                    "snapshot_status": {},
                    "metrics": {},
                }

        elif function_name in ["generate_alarm", "disable_interface", "enable_interface"]:
            from jnpr.junos.utils.config import Config
            with Config(dev, mode="exclusive") as cu:
                result = function(dev, cu, **parameters)

        else:
            # Execute other intents directly
            result = function(dev, **parameters)

        # Standardize result processing
        if isinstance(result, list):
            # Summarize status for list-based results
            summary_status = "success" if all(item.get("status") == "cleared" for item in result) else "partial"
            return {
                "summary": {"status": summary_status},
                "result": result,
            }
        elif isinstance(result, tuple):
            # Handle tuple-based results
            success, snapshot_status, metrics = result
            return {
                "summary": {"status": "success" if success else "fail"},
                "snapshot_status": snapshot_status,
                "metrics": metrics,
            }
        elif isinstance(result, dict):
            # Handle dictionary-based results directly
            return result

        # Catch unexpected result formats
        logging.error(f"Unexpected result format from '{function_name}': {result}")
        return {"summary": {"status": "fail", "error": "Unexpected result format"}}

    except Exception as e:
        logging.error(f"Error executing intent '{function_name}' on device '{device_info['name']}': {e}")
        return {"summary": {"status": "fail", "error": str(e)}, "snapshot_status": {}, "metrics": {}}

    finally:
        if 'dev' in locals() and dev:
            dev.close()'''

def execute_intent(device_info, intent_details, function_name, global_creds, device_parameters):
    """
    Execute a specific intent for a given device, but only if the device is reachable.
    """

    # Merge parameters and remove duplicate keys
    parameters = {**intent_details.get("parameters", {}), **device_parameters}
    parameters.pop("device_name", None)

    # Fetch device credentials
    username, password = get_device_credentials(device_info, global_creds)
    if not username or not password:
        logging.error(f"Device '{device_info.get('name')}' missing credentials.")
        return {"summary": {"status": "fail", "error": "Missing credentials"}, "snapshot_status": {}, "metrics": {}}

    # Step 1: Attempt to connect to the device (Handles reachability & SSH checks)
    dev = connect_to_device(device_info["host"], username, password)

    # ✅ If the device is unreachable, prevent intent execution
    if not dev or not dev.connected:
        logging.error(f"Skipping execution. Device '{device_info['name']}' is not reachable or SSH is disabled.")
        return {"summary": {"status": "fail", "error": "Device unreachable"}, "snapshot_status": {}, "metrics": {}}

    logging.info(f"✅ Device '{device_info['name']}' connection validated. Executing intent '{function_name}'.")

    try:
        # Dynamically load the intent function
        intent_module = importlib.import_module("intent_functions")
        function = getattr(intent_module, function_name, None)

        if not function:
            logging.error(f"❌ Intent function '{function_name}' not found.")
            return {"summary": {"status": "fail", "error": "Function not found"}, "snapshot_status": {}, "metrics": {}}

        # Handle special logic for specific intents
        if function_name == "compare_pre_post_event_states":
            hostname = dev.hostname
            pre_event_file = f"./snapshots/pre/{hostname}_pre.xml"
            post_event_file = f"./snapshots/post/{hostname}_post.xml"

            # Validate file existence
            missing_files = [f for f in [pre_event_file, post_event_file] if not os.path.exists(f)]
            if missing_files:
                error_message = f"❌ File(s) not found: {', '.join(missing_files)}"
                logging.error(error_message)
                return {"summary": {"status": "fail", "error": error_message}, "snapshot_status": {}, "metrics": {}}

            # Compare files
            try:
                logging.info(f"🔍 Comparing state between pre-event file: {pre_event_file} and post-event file: {post_event_file}.")
                result = function(pre_event_file=pre_event_file, post_event_file=post_event_file)
                return {
                    "summary": {"status": "success" if result["status"] == "pass" else "fail"},
                    "snapshot_status": {},
                    "metrics": result.get("diff", {}),
                    "diff_file": result.get("diff_file", None),
                }
            except Exception as e:
                logging.error(f"❌ Error during state comparison: {e}")
                return {"summary": {"status": "fail", "error": str(e)}, "snapshot_status": {}, "metrics": {}}

        elif function_name in ["generate_alarm", "disable_interface", "enable_interface"]:
            from jnpr.junos.utils.config import Config
            with Config(dev, mode="exclusive") as cu:
                result = function(dev, cu, **parameters)

        else:
            # Execute other intents directly
            result = function(dev, **parameters)

        # ✅ Standardize result processing
        if isinstance(result, list):
            # Summarize status for list-based results
            summary_status = "success" if all(item.get("status") == "cleared" for item in result) else "partial"
            return {"summary": {"status": summary_status}, "result": result}

        elif isinstance(result, tuple):
            # Handle tuple-based results
            success, snapshot_status, metrics = result
            return {"summary": {"status": "success" if success else "fail"}, "snapshot_status": snapshot_status, "metrics": metrics}

        elif isinstance(result, dict):
            # Handle dictionary-based results directly
            return result

        # ❌ Catch unexpected result formats
        logging.error(f"❌ Unexpected result format from '{function_name}': {result}")
        return {"summary": {"status": "fail", "error": "Unexpected result format"}}

    except Exception as e:
        logging.error(f"❌ Error executing intent '{function_name}' on device '{device_info['name']}': {e}")
        return {"summary": {"status": "fail", "error": str(e)}, "snapshot_status": {}, "metrics": {}}

    finally:
        # ✅ Ensure the device connection is closed properly
        if 'dev' in locals() and dev:
            dev.close()
            logging.info(f"🔌 Connection to device '{device_info['name']}' closed.")

# Concurrent Execution
def execute_intents_for_device(device_name, intents_registry, intent_sequence, creds, global_creds):
    """
    Executes intents for a single device sequentially.
    """
    device_info = next((d for d in creds["devices"] if d["name"] == device_name), None)
    if not device_info:
        logging.error(f"Device '{device_name}' not found in device credentials.")
        return {device_name: {"status": "failed", "details": []}}

    summary = {"status": "completed", "details": []}
    sequence = intent_sequence.get(device_name, [])

    logging.info(f"Starting sequential execution for device '{device_name}'.")

    for intent in sequence:
        intent_name = intent["intent"]
        iterations = intent.get("iterations", 1)
        sleep_timer = intent.get("sleep_timer", 0)
        parameters = intent.get("parameters", {})
        active = intent.get("active", "yes").strip().lower()

        # Skip inactive intents
        if active != "yes":
            logging.info(f"Skipping inactive intent '{intent_name}' for device '{device_name}'.")
            continue

        intent_details = intents_registry.get("intents", {}).get(intent_name, {})
        function_name = intent_details.get("function")

        # Track intent execution status
        intent_status = {"intent": intent_name, "iterations": [], "status": "success"}

        for iteration in range(iterations):
            logging.info(f"Executing intent '{intent_name}' for device '{device_name}' - Iteration {iteration + 1}/{iterations}.")
            try:
                # Execute intent and capture the result
                result = execute_intent(
                    device_info, intent_details, function_name, global_creds, parameters
                )
                iteration_status = result.get("summary", {}).get("status", "fail")
                intent_status["iterations"].append({"iteration": iteration + 1, "status": iteration_status})

                if iteration_status != "success":
                    intent_status["status"] = "failed"
                    summary["status"] = "failed"

            except Exception as e:
                logging.error(f"Error executing intent '{intent_name}' on device '{device_name}': {e}")
                intent_status["iterations"].append({"iteration": iteration + 1, "status": "fail"})
                intent_status["status"] = "failed"
                summary["status"] = "failed"

            # Sleep between iterations
            if iteration < iterations - 1:
                logging.info(f"Sleeping for {sleep_timer} seconds before the next iteration.")
                time.sleep(sleep_timer)

        # Add intent status to the device summary
        summary["details"].append(intent_status)

    logging.info(f"Completed execution for device '{device_name}'.")
    return {device_name: summary}



# Main Function
if __name__ == "__main__":
    intents_registry_file = "intents_registry.json"
    intent_sequence_file = "device_intent.yaml"
    creds_file = "device_creds.yaml"
    intents_registry = load_json(intents_registry_file)
    intent_sequences = load_yaml(intent_sequence_file)
    creds = load_yaml(creds_file)

    if not intents_registry or not intent_sequences or not creds:
        logging.error("Failed to load required files.")
        exit(1)

    try:
        validate_intents(intents_registry, intent_sequences.get("intent_sequence", {}), creds)
    except ValueError as e:
        logging.error(f"Validation error: {e}")
        exit(1)

    execute_all_intents_round_robin(intents_registry_file, intent_sequence_file, creds_file)


