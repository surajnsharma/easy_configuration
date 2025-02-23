#intent_functions.py#
import logging
import time
from jnpr.junos import Device
from jnpr.junos.exception import ConfigLoadError, CommitError, RpcError,ConnectRefusedError, ConnectError, ConnectTimeoutError, ProbeError
import socket


import os
from jnpr.junos.exception import RpcError
from lxml import etree  # For pretty-printing XML



def handle_intent_errors(e, intent_name, device_name, context=""):
    """
    Handle errors during intent execution, including configuration-related errors.
    """
    if isinstance(e, ConfigLoadError):
        logging.error(
            f"ConfigLoadError while executing '{intent_name}' on device '{device_name}': "
            f"Severity: {getattr(e, 'severity', 'N/A')}, Element: {getattr(e, 'bad_element', 'N/A')}, "
            f"Message: {getattr(e, 'message', 'N/A')}. Context: {context}"
        )
        if hasattr(e, "xml"):
            logging.debug(f"Error XML details: {e.xml}")
        return "ConfigLoadError"
    elif isinstance(e, CommitError):
        logging.error(
            f"CommitError while executing '{intent_name}' on device '{device_name}': {e}. Context: {context}"
        )
        return "CommitError"
    elif isinstance(e, RpcError):
        logging.error(
            f"RpcError while executing '{intent_name}' on device '{device_name}': {e}. Context: {context}"
        )
        return "RpcError"
    else:
        logging.error(
            f"Unexpected error while executing '{intent_name}' on device '{device_name}': {e}. Context: {context}"
        )
        return "UnknownError"
def handle_config_load(cu, device_name, config_command, intent_name, retries=3, delay=5):
    """
    Handle the process of loading a configuration with retries in case of failures.
    """
    for attempt in range(1, retries + 1):
        try:
            cu.load(config_command, format="set")
            cu.commit(timeout=30)
            logging.info(
                f"Configuration successfully loaded for intent '{intent_name}' on device '{device_name}'."
            )
            return True
        except (ConfigLoadError, CommitError, RpcError) as e:
            handle_intent_errors(e, intent_name, device_name, context=f"Command: {config_command}")
            if attempt < retries:
                logging.warning(
                    f"Retrying configuration load for intent '{intent_name}' on device '{device_name}' after {delay} seconds "
                    f"(Attempt {attempt}/{retries})..."
                )
                time.sleep(delay)
            else:
                logging.error(
                    f"Maximum retries reached for configuration load. Intent '{intent_name}' failed on device '{device_name}'."
                )
                return False
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            return False

def connect_to_device(host, username, password, retries=1, delay=5):
    for attempt in range(retries):
        try:
            dev = Device(host=host, user=username, passwd=password)
            dev.open()
            logging.info(f"Successfully connected to {host}.")
            return dev
        except Exception as e:
            logging.error(f"Connection attempt {attempt + 1} failed for {host}: {e}")
            time.sleep(delay)
    return None


def is_device_reachable(host, timeout=3):
    """
    Checks if a device is reachable via ICMP (ping).
    Returns True if reachable, False otherwise.
    """
    response = os.system(f"ping -c 1 -W {timeout} {host} > /dev/null 2>&1")
    return response == 0  # 0 means success


'''def connect_to_device(host, username, password, retries=3, delay=5):
    """
    Attempts to connect to a network device. If the device is unreachable, it will not execute the intent.

    Returns:
        Device object if successful, else None.
    """

    def is_device_reachable(host, timeout=3):
        """Check if the device is reachable via ICMP (ping)."""
        response = os.system(f"ping -c 1 -W {timeout} {host} > /dev/null 2>&1")
        return response == 0  # 0 means success

    def is_ssh_port_open(host, port=22, timeout=3):
        """Check if SSH port 22 is open."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError):
            return False

    # Step 1: Ensure device is reachable
    if not is_device_reachable(host):
        logging.error(f"Device {host} is not reachable. Skipping execution.")
        with open("skipped_devices.log", "a") as log_file:
            log_file.write(f"{host} - Unreachable\n")
        return None  # Return None to prevent execution

    # Step 2: Ensure SSH is enabled
    if not is_ssh_port_open(host):
        logging.error(f"SSH port 22 is closed on {host}. Skipping execution.")
        with open("skipped_devices.log", "a") as log_file:
            log_file.write(f"{host} - SSH Closed\n")
        return None  # Return None to prevent execution

    # Step 3: Attempt SSH connection
    for attempt in range(1, retries + 1):
        try:
            dev = Device(host=host, user=username, passwd=password)
            dev.open()

            if dev.connected:
                logging.info(f"Successfully connected to {host} (Attempt {attempt}/{retries}).")
                return dev
            else:
                logging.warning(f"Connected to {host} but dev.connected is False. Retrying...")

        except ConnectRefusedError:
            logging.error(f"Connection refused for {host}. Ensure SSH is enabled.")
        except ConnectTimeoutError:
            logging.error(f"Connection timeout for {host}. Check network reachability.")
        except ConnectError as e:
            logging.error(f"General connection error for {host}: {e}")
        except ProbeError:
            logging.error(f"Cannot probe the device {host}. Device might be unreachable.")
        except paramiko.ssh_exception.SSHException as e:
            logging.error(f"SSH error for {host}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error while connecting to {host}: {e}")

        time.sleep(delay * attempt)  # Exponential backoff for retries

    logging.error(f"Failed to connect to {host} after {retries} attempts.")
    with open("skipped_devices.log", "a") as log_file:
        log_file.write(f"{host} - Connection Failed\n")
    return None  # Return None to prevent execution'''


def generate_alarm(device, cu, fpc_slot, pic_slot, ports, **kwargs):
    """
    Generates alarms on specified ports by simulating a high-power optics insert.
    If an alarm is found, executes corrective commands to disable the alarm.
    """
    rpc_commands = [
        "request pfe execute command \"test picd optics fpc_slot 0 pic_slot 0 port 1 cmd oir_enable\" target fpc0",
        "request pfe execute command \"test picd optics fpc_slot 0 pic_slot 0 port 1 cmd remove\" target fpc0",
        "request pfe execute command \"test picd optics fpc_slot 0 pic_slot 0 port 1 cmd insert\" target fpc0",
        "request pfe execute command \"test picd optics fpc_slot 0 pic_slot 0 port 1 cmd oir_disable\" target fpc0"
    ]

    def execute_corrective_command(device, port, commands, alarm_text, retries=3):
        attempt = 0
        while attempt < retries:
            attempt += 1
            try:
                port_number = port.split("/")[-1]
                for command in commands:
                    corrected_command = command.replace('port 1', f'port {port_number}')
                    logging.info(f"Executing corrective command: {corrected_command}")
                    device.rpc.cli(command=corrected_command)
                    logging.info(f"Command executed successfully for port-{port}: {corrected_command}")

                time.sleep(3)
                if not specific_alarm_still_exists(device, port, alarm_text):
                    logging.info(f"Alarm cleared for port-{port}: {alarm_text}")
                    return {"port": port, "status": "cleared", "description": "Alarm cleared after corrective action"}
                else:
                    logging.warning(f"Alarm still exists for port-{port}. Retrying... (Attempt {attempt}/{retries})")
            except Exception as e:
                logging.error(f"Error during corrective command execution for port-{port}: {e}")

        logging.error(f"Alarm persists for port-{port} after {retries} retries.")
        return {"port": port, "status": "failure", "description": "Alarm not cleared after retries"}

    def specific_alarm_still_exists(device, port, alarm_text):
        try:
            alarms = device.rpc.get_alarm_information()
            for alarm in alarms.xpath('.//alarm-description'):
                if port in alarm.text and alarm_text in alarm.text:
                    return True
        except Exception as e:
            logging.error(f"Error checking specific alarm for port-{port}: {e}")
        return False

    alarm_results = []
    all_cleared = True
    for port in ports:
        port_identifier = f"{fpc_slot}/{pic_slot}/{port}"
        logging.info(f"Processing port {port_identifier}")
        try:
            simulate_command = f"test picd optics fpc_slot {fpc_slot} pic_slot {pic_slot} port {port} cmd simulate_high_power_optics_insert"
            device.rpc.request_pfe_execute(target="fpc0", command=simulate_command)
            logging.info(f"Simulated alarm for port {port}")

            alarms = device.rpc.get_alarm_information()
            alarm_found = False
            for alarm in alarms.xpath(".//alarm-description"):
                if f"port-{port_identifier}" in alarm.text and "Optics Power Fault" in alarm.text:
                    logging.info(f"Alarm detected for port {port_identifier}: {alarm.text.strip()}")
                    alarm_results.append({"port": port_identifier, "status": "alarm generated", "description": alarm.text.strip()})
                    alarm_found = True

                    corrective_result = execute_corrective_command(device, port_identifier, rpc_commands, "Optics Power Fault")
                    alarm_results.append(corrective_result)
                    if corrective_result["status"] != "cleared":
                        all_cleared = False
                    break

            if not alarm_found:
                logging.warning(f"No alarm detected for port {port_identifier}")
                alarm_results.append({"port": port_identifier, "status": "failure", "description": "No alarm detected"})
                all_cleared = False
        except Exception as e:
            logging.error(f"Error while processing port {port_identifier}: {e}")
            alarm_results.append({"port": port_identifier, "status": "failure", "error": str(e)})
            all_cleared = False

    overall_status = "success" if all_cleared else "fail"
    return {
        "summary": {"status": overall_status},
        "results": alarm_results
    }


def enable_interface(dev, cu, **kwargs):
    def build_interface_names(fpc_slot, pic_slot, ports):
        """
        Generate interface names based on fpc_slot, pic_slot, and ports.
        Handles ports with subunits like "20:0".
        """
        interfaces = []
        for port in ports:
            try:
                port = str(port).strip()
                if ':' in port:
                    base_port, subunit = port.split(':')
                    interfaces.append(f"et-{fpc_slot}/{pic_slot}/{int(base_port)}:{subunit}")
                else:
                    interfaces.append(f"et-{fpc_slot}/{pic_slot}/{int(port)}")
            except ValueError as e:
                logging.error(f"Invalid port value '{port}': {e}")
            except Exception as e:
                logging.error(f"Unexpected error while processing port '{port}': {e}")
        return interfaces


    fpc_slot = kwargs.get("fpc_slot")
    pic_slot = kwargs.get("pic_slot")
    ports = kwargs.get("ports", [])
    interface_name = kwargs.get("interface_name")

    # Build the list of interfaces
    if not interface_name and fpc_slot is not None and pic_slot is not None and ports:
        interface_list = build_interface_names(fpc_slot, pic_slot, ports)
    else:
        interface_list = [interface_name] if isinstance(interface_name, str) else interface_name or []

    if not interface_list:
        logging.error("No interfaces provided for enable_interface.")
        return {"summary": {"status": "fail"}, "snapshot_status": {"enable_interface": "no interfaces provided"}}

    # Validate interfaces on the device
    valid_interfaces = []
    for iface in interface_list:
        try:
            rpc_reply = dev.rpc.get_interface_information(interface_name=iface, terse=True)
            if rpc_reply.xpath(f".//physical-interface[name='{iface}']"):
                logging.info(f"Interface '{iface}' exists on device '{dev.hostname}'.")
                valid_interfaces.append(iface)
            else:
                logging.warning(f"Interface '{iface}' does not exist on device '{dev.hostname}'. Skipping.")
        except Exception as e:
            logging.error(f"Failed to validate interface '{iface}' on device '{dev.hostname}': {e}")

    if not valid_interfaces:
        logging.error(f"No valid interfaces found for enable_interface on device '{dev.hostname}'.")
        return {"summary": {"status": "fail"}, "snapshot_status": {"enable_interface": "no valid interfaces"}}

    # Enable the interfaces
    operation_status = {}
    for iface in valid_interfaces:
        command = f"delete interfaces {iface} disable"
        success = handle_config_load(cu, dev.hostname, command, "enable_interface", retries=3, delay=5)
        if not success:
            logging.error(f"Failed to enable interface '{iface}' on device '{dev.hostname}'.")
            operation_status[iface] = "fail"
            continue

        # Verify that the interface is up
        for attempt in range(5):
            try:
                rpc_reply = dev.rpc.get_interface_information(interface_name=iface, terse=True)
                admin_status = rpc_reply.xpath(f".//physical-interface[name='{iface}']/admin-status")[0].text
                oper_status = rpc_reply.xpath(f".//physical-interface[name='{iface}']/oper-status")[0].text
                lacp_status = rpc_reply.xpath(f".//physical-interface[name='{iface}']/ether-options/lacp-status")

                # Log detailed RPC reply for debugging
                logging.debug(f"RPC Reply for '{iface}' (Attempt {attempt + 1}/5): {etree.tostring(rpc_reply, pretty_print=True).decode()}")

                # Check statuses
                if admin_status == "up" and oper_status == "up":
                    logging.info(f"Interface '{iface}' is operationally up on device '{dev.hostname}'.")
                    operation_status[iface] = "success"
                    break
                elif lacp_status and lacp_status[0].text != "active":
                    logging.warning(f"LACP status for '{iface}' is not active. Retrying...")
                else:
                    logging.warning(f"Interface '{iface}' - Admin: {admin_status}, Oper: {oper_status}. Retrying...")
            except Exception as e:
                logging.error(f"Error during RPC call for '{iface}' on attempt {attempt + 1}: {e}")
            time.sleep(5)
        else:
            logging.error(f"Interface '{iface}' failed to become operationally up on device '{dev.hostname}'.")
            operation_status[iface] = "fail"

    # Summarize the operation status
    overall_status = "success" if all(status == "success" for status in operation_status.values()) else "partial"
    print(f"**overall_status: {overall_status}")
    print(f"**operation_status: {operation_status}")
    return {
        "summary": {"status": overall_status},
        "snapshot_status": {"enable_interface": operation_status},
    }



def disable_interface(dev, cu, **kwargs):
    """
    Disable network interfaces based on provided parameters.
    """
    def build_interface_names(fpc_slot, pic_slot, ports):
        """
        Generate interface names based on fpc_slot, pic_slot, and a list of ports.
        Always treats ports as strings.
        """
        interfaces = []
        for port in ports:
            try:
                # Convert port to string and ensure proper formatting
                port = str(port).strip()

                # Handle ports with subunits (e.g., "20:0")
                if ':' in port:
                    base_port, subunit = port.split(':')
                    interfaces.append(f"et-{fpc_slot}/{pic_slot}/{int(base_port)}:{subunit}")
                else:
                    interfaces.append(f"et-{fpc_slot}/{pic_slot}/{int(port)}")
            except ValueError as e:
                logging.error(f"Invalid port value '{port}': {e}")
            except Exception as e:
                logging.error(f"Unexpected error while processing port '{port}': {e}")
        logging.debug(f"Generated interfaces: {interfaces}")
        return interfaces

    fpc_slot = kwargs.get("fpc_slot")
    pic_slot = kwargs.get("pic_slot")
    ports = kwargs.get("ports", [])
    interface_name = kwargs.get("interface_name")

    if not interface_name and fpc_slot is not None and pic_slot is not None and ports:
        interface_list = build_interface_names(fpc_slot, pic_slot, ports)
    else:
        interface_list = [interface_name] if isinstance(interface_name, str) else interface_name or []

    valid_interfaces = []
    for iface in interface_list:
        try:
            rpc_reply = dev.rpc.get_interface_information(interface_name=iface, terse=True)
            if rpc_reply.xpath(f".//physical-interface[name='{iface}']"):
                logging.info(f"Interface '{iface}' exists on device '{dev.hostname}'.")
                valid_interfaces.append(iface)
            else:
                logging.warning(f"Interface '{iface}' does not exist on device '{dev.hostname}'. Skipping.")
        except Exception as e:
            logging.error(f"Failed to validate interface '{iface}' on device '{dev.hostname}': {e}")

    if not valid_interfaces:
        logging.error(f"No valid interfaces found for disable_interface on device '{dev.hostname}'.")
        return {"summary": {"status": "fail"}, "snapshot_status": {"disable_interface": "no valid interfaces"}}

    operation_status = {}
    for iface in valid_interfaces:
        command = f"set interfaces {iface} disable"
        success = handle_config_load(cu, dev.hostname, command, "disable_interface", retries=3, delay=5)
        if not success:
            logging.error(f"Failed to disable interface '{iface}' on device '{dev.hostname}'.")
            operation_status[iface] = "fail"
            continue

        for attempt in range(5):
            rpc_reply = dev.rpc.get_interface_information(interface_name=iface, terse=True)
            admin_status = rpc_reply.xpath(f".//physical-interface[name='{iface}']/admin-status")[0].text
            oper_status = rpc_reply.xpath(f".//physical-interface[name='{iface}']/oper-status")[0].text

            if admin_status == "down" and oper_status == "down":
                logging.info(f"Interface '{iface}' is operationally down on device '{dev.hostname}'.")
                operation_status[iface] = "success"
                break
            else:
                logging.warning(f"Interface '{iface}' is not down yet. Retrying... ({attempt + 1}/5)")
                time.sleep(5)
        else:
            logging.error(f"Interface '{iface}' failed to become operationally down on device '{dev.hostname}'.")
            operation_status[iface] = "fail"

    overall_status = "success" if all(status == "success" for status in operation_status.values()) else "partial"
    return {
        "summary": {"status": overall_status},
        "snapshot_status": {"disable_interface": operation_status},
    }


def execute_custom_commands(dev, cu=None, device_name=None, **kwargs):
    """
    Execute a list of custom commands on the device in a specified format,
    and save the output in the provided output directory with the correct snapshot_type.

    Args:
        dev: Device connection object.
        cu: Optional configuration object.
        device_name: Device name for custom filenames.
        kwargs: Additional arguments (commands, format, output_dir, snapshot_type).
    """
    # Use the provided device name or fallback to device hostname
    device_name = device_name or getattr(dev, "hostname", "unknown_device")
    logging.debug(f"Device name resolved as: {device_name}")

    # Retrieve parameters
    commands = kwargs.get("commands", [])
    output_format = kwargs.get("format", "text").lower()  # Default to "text" format
    output_dir = kwargs.get("output_dir", "./snapshots")  # Default output directory
    snapshot_type = kwargs.get("snapshot_type", "general").lower()  # Default to "general"

    # Validate commands
    if not commands:
        logging.error("No custom commands provided for execution.")
        return {"summary": {"status": "fail", "reason": "No commands provided"}, "snapshot_status": {}}

    # Ensure the output directory exists, including the snapshot type subdirectory
    output_dir = os.path.join(output_dir, snapshot_type)
    os.makedirs(output_dir, exist_ok=True)

    # Build output file path dynamically based on snapshot_type and device_name
    output_file = os.path.join(output_dir, f"{device_name}_{snapshot_type}.{output_format}")

    command_results = {}
    overall_output = f"Custom Commands Snapshot for {device_name} ({snapshot_type.upper()})\n{'=' * 40}\n"

    # Execute commands
    for command in commands:
        try:
            logging.info(f"Executing command: {command} with format: {output_format}")
            if output_format == "xml":
                # Execute the command in XML format
                response = dev.rpc.cli(command, format="xml")
                response_output = etree.tostring(response, pretty_print=True).decode("utf-8")
            else:
                # Default to text format
                response_output = dev.cli(command, warning=False)
                if isinstance(response_output, bytes):
                    response_output = response_output.decode("utf-8")  # Decode bytes to string

            # Append the command and its output to the overall content
            overall_output += f"\nCommand: {command}\n{'-' * 40}\n{response_output}\n{'-' * 40}\n"
            command_results[command] = {"status": "success"}
            logging.info(f"Command '{command}' executed successfully.")
        except Exception as e:
            logging.error(f"Error executing command '{command}': {e}")
            overall_output += f"\nCommand: {command}\nERROR: {e}\n{'-' * 40}\n"
            command_results[command] = {"status": "fail", "error": str(e)}

    # Save the overall output to a file
    try:
        with open(output_file, "w", encoding="utf-8") as file:
            file.write(overall_output)
        logging.info(f"Custom commands output saved to {output_file}")
    except Exception as e:
        logging.error(f"Failed to save command outputs to {output_file}: {e}")

    # Determine overall status
    overall_status = "success" if all(result["status"] == "success" for result in command_results.values()) else "partial"
    return {
        "summary": {"status": overall_status},
        "snapshot_status": {"execute_custom_commands": command_results},
    }
'''def snapshot_device_state(dev, cu=None, device_name=None, **kwargs):
    """
    Capture a snapshot of the device state and save it locally in the specified format (XML or text).
    """

    # Ensure the device_name is passed or fallback to dev.hostname
    if not device_name:
        device_name = getattr(dev, "hostname", None)
    if not device_name:
        raise ValueError("Device name is not provided and cannot be inferred from the device object.")

    # Commands to execute
    commands = [
        {
            "description": "System Processes",
            "cli": "show system processes extensive",
        },
        {
            "description": "BGP Summary",
            "cli": "show bgp summary",
        },
        {
            "description": "Interfaces Terse",
            "cli": "show interfaces terse",
        },
        {
            "description": "Chassis Routing Engine",
            "cli": "show chassis routing-engine",
        },
        {
            "description": "Route Summary",
            "cli": "show route summary",
        },
    ]

    save_to_file = kwargs.get("save_to_file", True)
    output_dir = kwargs.get("output_dir", "./snapshots")
    snapshot_type = kwargs.get("snapshot_type", "pre")  # Capture snapshot type (pre/post)
    output_format = kwargs.get("format", "text").lower()  # Default to text

    # Save snapshots in subdirectories based on snapshot type
    output_dir = os.path.join(output_dir, snapshot_type)
    os.makedirs(output_dir, exist_ok=True)

    file_extension = "xml" if output_format == "xml" else "txt"
    snapshot_file_path = os.path.join(output_dir, f"{device_name}_{snapshot_type}.{file_extension}")
    snapshot_status = {}

    try:
        if output_format == "xml":
            # Begin XML structure
            snapshot_content = f"<snapshot device='{device_name}' type='{snapshot_type}'>\n"
        else:
            snapshot_content = f"Snapshot for {device_name}\n" + "=" * 40 + "\n"

        for command in commands:
            description = command["description"]
            cli_command = command["cli"]

            try:
                logging.info(f"Running command for {description}")

                # Use the appropriate method based on format
                if output_format == "xml":
                    # Use the RPC CLI method with XML format
                    result = dev.rpc.cli(cli_command, format="xml")
                    output = etree.tostring(result, pretty_print=True).decode("utf-8")
                else:
                    # Use CLI output for text
                    output = dev.cli(cli_command, warning=False)
                    if isinstance(output, bytes):
                        output = output.decode("utf-8")

                if output_format == "xml":
                    snapshot_content += f"  <command description='{description}'>\n"
                    snapshot_content += f"{output}\n  </command>\n"
                else:
                    snapshot_content += f"\n{description}:\n" + "-" * 40 + "\n"
                    snapshot_content += output + "\n" + "-" * 40 + "\n"
                logging.info(f"Command for {description} executed successfully.")
                snapshot_status[description] = "success"
            except Exception as e:
                logging.error(f"Error running command for {description}: {e}")
                if output_format == "xml":
                    snapshot_content += f"  <command description='{description}' error='{e}' />\n"
                else:
                    snapshot_content += f"\n{description}: ERROR - {e}\n"
                snapshot_status[description] = "error"
        if output_format == "xml":
            # End XML structure
            snapshot_content += "</snapshot>"

        if save_to_file:
            with open(snapshot_file_path, "w", encoding="utf-8") as snapshot_file:
                snapshot_file.write(snapshot_content)
            logging.info(f"Snapshot saved locally at {snapshot_file_path}")

        return {"snapshot_status": snapshot_status}

    except Exception as e:
        logging.error(f"Error creating snapshot: {e}")
        return {"snapshot_status": {"error": str(e)}}'''
def snapshot_device_state(dev, cu=None, device_name=None, **kwargs):
    """
    Capture a snapshot of the device state using predefined commands and save it locally
    in the specified format (XML or text).
    Args:
        dev: Device connection object.
        cu: Optional configuration object.
        device_name: Device name for custom filenames.
        kwargs: Additional arguments (format, output_dir, snapshot_type).
    Returns:
        dict: Summary of the snapshot creation process.
    """
    # Resolve device name
    device_name = device_name or getattr(dev, "hostname", "unknown_device")
    logging.debug(f"Device name resolved as: {device_name}")

    # Predefined commands to execute
    commands = [
        "show system processes extensive",
        "show bgp summary",
        "show interfaces terse",
        "show chassis routing-engine",
        "show route summary",
    ]

    # Retrieve additional parameters
    output_format = kwargs.get("format", "text").lower()  # Default to "text"
    output_dir = kwargs.get("output_dir", "./snapshots")  # Default output directory
    snapshot_type = kwargs.get("snapshot_type", "general").lower()  # Default to "general"

    # Ensure the output directory exists, including the snapshot type subdirectory
    output_dir = os.path.join(output_dir, snapshot_type)
    os.makedirs(output_dir, exist_ok=True)

    # Build output file path dynamically based on snapshot_type and device_name
    file_extension = "xml" if output_format == "xml" else "txt"
    output_file = os.path.join(output_dir, f"{device_name}_{snapshot_type}.{file_extension}")

    snapshot_status = {}
    overall_output = f"Snapshot for {device_name} ({snapshot_type.upper()})\n{'=' * 40}\n"

    # Execute predefined commands
    for command in commands:
        try:
            logging.info(f"Executing command: {command} with format: {output_format}")
            if output_format == "xml":
                # Execute the command in XML format
                response = dev.rpc.cli(command, format="xml")
                response_output = etree.tostring(response, pretty_print=True).decode("utf-8")
            else:
                # Default to text format
                response_output = dev.cli(command, warning=False)
                if isinstance(response_output, bytes):
                    response_output = response_output.decode("utf-8")  # Decode bytes to string

            # Append the command and its output to the overall content
            overall_output += f"\nCommand: {command}\n{'-' * 40}\n{response_output}\n{'-' * 40}\n"
            snapshot_status[command] = {"status": "success"}
            logging.info(f"Command '{command}' executed successfully.")
        except Exception as e:
            logging.error(f"Error executing command '{command}': {e}")
            overall_output += f"\nCommand: {command}\nERROR: {e}\n{'-' * 40}\n"
            snapshot_status[command] = {"status": "fail", "error": str(e)}

    # Save the overall output to a file
    try:
        with open(output_file, "w", encoding="utf-8") as file:
            file.write(overall_output)
        logging.info(f"Snapshot saved to {output_file}")
    except Exception as e:
        logging.error(f"Failed to save snapshot to {output_file}: {e}")

    # Determine overall status
    overall_status = "success" if all(status["status"] == "success" for status in snapshot_status.values()) else "partial"
    return {
        "summary": {"status": overall_status},
        "snapshot_status": snapshot_status,
    }

def compare_pre_post_event_states(pre_event_file, post_event_file, **kwargs):
    """
    Compare pre-event and post-event state files with mixed CLI outputs.

    Args:
        pre_event_file (str): Path to the pre-event state file.
        post_event_file (str): Path to the post-event state file.

    Returns:
        dict: Results of the comparison, including detected differences or errors.
    """
    import difflib
    import os

    logging.info(f"**Pre-event file: {pre_event_file}")
    logging.info(f"**Post-event file: {post_event_file}")
    def parse_mixed_content(file_path):
        parsed_data = {}
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                content = file.read()
            sections = content.split("Command:")
            for section in sections:
                if section.strip():
                    lines = section.splitlines()
                    command = lines[0].strip()  # First line is the command
                    output = "\n".join(
                        line for line in lines[1:] if line.strip() not in {"========================================", "Not Present"}
                    ).strip()  # Filter placeholder lines
                    parsed_data[command] = output or "Command not found"
        except Exception as e:
            logging.error(f"Error parsing mixed content from {file_path}: {e}")
        return parsed_data
    try:
        # Validate file existence
        for file_path in [pre_event_file, post_event_file]:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"Required file '{file_path}' not found.")

        # Parse pre-event and post-event files
        pre_data = parse_mixed_content(pre_event_file)
        post_data = parse_mixed_content(post_event_file)

        # Collect all commands from both files
        all_commands = set(pre_data.keys()).union(set(post_data.keys()))

        """differences = []
        for command in all_commands:
            pre_output = pre_data.get(command, "Not Present")
            post_output = post_data.get(command, "Not Present")

            if pre_output != post_output:
                diff = "\n".join(
                    difflib.unified_diff(
                        pre_output.splitlines(),
                        post_output.splitlines(),
                        lineterm="",
                        fromfile=f"Pre-{command}",
                        tofile=f"Post-{command}",
                    )
                )
                differences.append(f"Differences in command '{command}':\n{diff}")"""
        differences = []
        for command in all_commands:
            pre_output = pre_data.get(command, "Command not found")
            post_output = post_data.get(command, "Command not found")

            if pre_output != post_output:
                diff = "\n".join(
                    difflib.unified_diff(
                        pre_output.splitlines(),
                        post_output.splitlines(),
                        lineterm="",
                        fromfile=f"Pre-{command}",
                        tofile=f"Post-{command}",
                    )
                )
                if diff.strip():  # Only include meaningful diffs
                    differences.append(f"Differences in command '{command}':\n{diff}")
        # Log and save differences
        if differences:
            diff_file = f"./snapshots/diffs/{os.path.basename(pre_event_file).replace('_pre.xml', '_diff.txt')}"
            os.makedirs(os.path.dirname(diff_file), exist_ok=True)
            with open(diff_file, "w", encoding="utf-8") as file:
                file.write("\n\n".join(differences))
            logging.warning(f"Differences saved to {diff_file}")
            return {"status": "fail", "diff": differences, "diff_file": diff_file}
        else:
            logging.info("State comparison successful. No differences found.")
            return {"status": "pass", "diff": ["No differences found."]}

    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        return {"status": "fail", "error": f"File not found: {e}"}
    except Exception as e:
        logging.error(f"Error comparing states: {e}")
        return {"status": "fail", "error": f"Comparison error: {e}"}
