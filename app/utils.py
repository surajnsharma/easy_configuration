#utils.py#
from flask import flash, redirect, url_for,current_app
from flask_login import current_user
from app import socketio
from functools import wraps
import os, re, paramiko, subprocess, time
import logging,ipaddress
from logging.handlers import RotatingFileHandler
from jnpr.junos.exception import ConnectError, ConnectAuthError, ConfigLoadError, CommitError, LockError, UnlockError,ConnectUnknownHostError,RpcError,RpcTimeoutError
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
import socket
from datetime import datetime, timedelta
from .models import db
import yaml,json
import psutil
from jinja2 import Environment, FileSystemLoader, TemplateNotFound
import hashlib
from lxml import etree
import xml.etree.ElementTree as ET
from jnpr.junos.utils.sw import SW
import gzip
import shutil
from werkzeug.utils import secure_filename
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

class DeviceConnectorClass:
    def __init__(self, hostname, ip, username, password, port=22, timeout=10, retries=1, retry_delay=5):
        self.hostname = hostname
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.retry_delay = retry_delay

    def is_valid_hostname(self):
        """ Checks if the provided hostname can be resolved. """
        try:
            socket.gethostbyname(self.hostname)
            return True
        except socket.error as e:
            logging.error(f"Failed to resolve hostname {self.hostname}: {e}")
            return False


    def connect_to_device(self):
        """Attempts to connect to the device using hostname first, then IP if hostname fails."""
        last_error = None

        for attempt in range(self.retries):
            try:
                # Attempt connection using hostname
                if self.is_valid_hostname():
                    logging.info(f"Attempting connection to {self.hostname} using hostname (Attempt {attempt + 1}).")
                    dev = Device(
                        host=self.hostname,
                        user=self.username,
                        passwd=self.password,
                        port=self.port,
                        timeout=self.timeout
                    )
                    dev.open()
                    logging.info(f"Successfully connected to {self.hostname} using hostname.")
                    return dev
                else:
                    logging.warning(f"Invalid hostname {self.hostname}. Attempting connection using IP.")

                # Attempt connection using IP
                dev = Device(
                    host=self.ip,
                    user=self.username,
                    passwd=self.password,
                    port=self.port,
                    timeout=self.timeout
                )
                dev.open()
                logging.info(f"Successfully connected to {self.ip} using IP.")
                return dev

            except (ConnectError, paramiko.SSHException, EOFError) as e:
                last_error = f"{e.__class__.__name__}: {str(e)}"
                logging.error(
                    f"Attempt {attempt + 1} failed for {self.hostname} or IP {self.ip}. Last error: {last_error}")
                if attempt < self.retries - 1:
                    logging.info(f"Retrying connection in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)

            except Exception as e:
                last_error = f"{e.__class__.__name__}: {str(e)}"
                logging.error(f"Unexpected error during connection attempt {attempt + 1}: {last_error}")
                break

        # Return None and last_error when all attempts fail
        error_message = f"All {self.retries} attempts to connect to {self.hostname or self.ip} failed. Last error: {last_error}"
        logging.error(error_message)
        return None, error_message

    def get_ssh_client(self):
        """
        Creates and returns an SSH client for the device.
        Returns:
            A connected `paramiko.SSHClient` instance or raises an error if unable to connect.
        """
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(hostname=self.ip, port=self.port, username=self.username, password=self.password,
                               timeout=self.timeout)
            logging.info(f"SSH connection established to {self.hostname or self.ip}.")
            return ssh_client
        except Exception as e:
            error_message = f"Failed to establish SSH connection to {self.hostname or self.ip}: {str(e)}"
            logging.error(error_message)
            raise ConnectionError(error_message)
    def close_connection(self, dev):
        """Closes the device connection if it is open."""
        try:
            if dev and dev.connected:
                dev.close()
                logging.info(f"Closed connection to {self.hostname} (or IP {self.ip})")
        except Exception as e:
            logging.error(f"Error closing connection to {self.hostname} or IP {self.ip}: {e}")




class RobotXMLParserClass:
    def __init__(self, upload_folder):
        self.upload_folder = upload_folder
        self.allowed_extensions = {'xml', 'gz'}
        self.patterns_to_match = [
            re.compile(r"\bnot running\b", re.IGNORECASE),
            re.compile(r"process-?\bnot\b-?\brunning", re.IGNORECASE),
            re.compile(r"error\s\d+", re.IGNORECASE),
            re.compile(r"TypeError:.* list or list-like", re.IGNORECASE),
            re.compile(r"'\".+?\" == \".+?\"' should be true", re.IGNORECASE),
            re.compile(r"<doc[^>]*>.*?Description:\s*(.*?)</doc>", re.DOTALL | re.IGNORECASE)
        ]
        self.exclusion_patterns = [
            re.compile(r"\bDictionary does not contain key\b", re.IGNORECASE)
        ]

    def allowed_file(self, filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in self.allowed_extensions

    def save_file(self, file, username):
        user_folder = os.path.join(self.upload_folder, username)
        os.makedirs(user_folder, exist_ok=True)
        file_path = os.path.join(user_folder, secure_filename(file.filename))
        file.save(file_path)
        return file_path

    def handle_gz_file(self, file_path):
        if file_path.endswith('.gz'):
            unzipped_file_path = file_path[:-3]
            with gzip.open(file_path, 'rb') as gz_file:
                with open(unzipped_file_path, 'wb') as xml_file:
                    shutil.copyfileobj(gz_file, xml_file)
            os.remove(file_path)
            return unzipped_file_path
        return file_path


    def get_patterns_to_match(self):
        """
        Expose the current patterns to match. Use this method
        wherever patterns are required in other methods.
        """
        return self.patterns_to_match



    def capture_failures_in_keywords(self, element, failure_messages=None):
        """
        Capture failures and matches in <msg> and <rpc-reply> elements.
        Args:
            element: The current XML element being processed.
            failure_messages: A list to store unique failure messages.
        """
        if failure_messages is None:
            failure_messages = []

        patterns = self.get_patterns_to_match()
        unique_messages = set()  # Ensure messages are unique within this invocation
        namespaces = {"xnm": "http://xml.juniper.net/xnm/1.1/xnm"}

        for msg in element.iter("msg"):
            timestamp = msg.get("timestamp", "No timestamp")
            msg_level = msg.get("level", "").upper()  # Check the message level
            msg_text = msg.text.strip() if msg.text else "No detailed message."

            # Skip informational messages (level=INFO)
            if msg_level == "INFO":
                continue

            # Check for failures with specific patterns
            if msg_level == "FAIL" or any(re.search(pattern, msg_text) for pattern in patterns):
                unique_messages.add((timestamp, msg_text))

            # Handle <rpc-reply> elements within the message
            rpc_reply_match = re.search(r"(<rpc-reply.*?>.*?</rpc-reply>)", msg_text, re.DOTALL)
            if rpc_reply_match:
                rpc_reply_content = re.sub(r"&[a-zA-Z]+;", "", rpc_reply_match.group(1))
                try:
                    rpc_reply = ET.fromstring(rpc_reply_content)
                    for error in rpc_reply.findall(".//xnm:error", namespaces):
                        error_msg = error.findtext("xnm:message", "No detailed message.", namespaces).strip()
                        if any(re.search(pattern, error_msg) for pattern in patterns):
                            unique_messages.add((timestamp, error_msg))
                except ET.ParseError:
                    continue

        # Add unique messages to failure_messages
        for timestamp, message in unique_messages:
            if not any(f["message"] == message for f in failure_messages):  # Avoid duplicates
                failure_messages.append({"timestamp": timestamp, "message": message})

        # Recursively process child elements
        for child in element:
            self.capture_failures_in_keywords(child, failure_messages)

    def parse_robot_xml(self, xml_content=None):
        """
        Parse XML content to capture general failures and test-specific failures.
        Args:
            xml_content: XML content as a string.
        Returns:
            str: A formatted string containing all captured failures.
        """

        def is_excluded(message):
            return any(pattern.search(message) for pattern in self.exclusion_patterns)

        try:
            tree = ET.ElementTree(ET.fromstring(xml_content))
        except ET.ParseError as e:
            raise ValueError(f"Error parsing XML: {e}")

        root = tree.getroot()
        output = []
        general_failures = []

        # Capture general failures
        self.capture_failures_in_keywords(root, failure_messages=general_failures)

        if general_failures:
            output.append("=> General Failures:")
            for failure in general_failures:
                if not is_excluded(failure["message"]):
                    output.append(f"[{failure['timestamp']}] - {failure['message']}")

        # Process each test case
        for test in root.iter("test"):
            test_name = test.get("name")
            failure_messages = []
            self.capture_failures_in_keywords(test, failure_messages)

            if failure_messages:
                # Fetch the <doc> content for the test case
                doc = test.find("doc")
                doc_description = None
                if doc is not None:
                    doc_text = ET.tostring(doc, encoding="unicode", method="xml")
                    description_match = re.search(
                        r"<doc[^>]*>\s*(.*?)\s*</doc>", doc_text, re.DOTALL | re.IGNORECASE
                    )
                    if description_match:
                        doc_description = re.sub(r"\s+", " ", description_match.group(1).strip())

                # Add test case header
                output.append(f"=> {test_name} encountered the following failures:")

                # Add description only if there are failures
                if doc_description:
                    cleaned_description = re.sub(r"x-cmd.*", "", doc_description)
                    output.append(f"[TestCase Description] - {cleaned_description.strip()}")

                for failure in failure_messages:
                    if not is_excluded(failure["message"]):
                        output.append(f"[{failure['timestamp']}] - {failure['message']}")

        if not output:
            output.append("No errors found.")
        return "\n".join(output)

    def suggest_corrective_action(self, error_message, corrective_actions):
        """Suggest corrective actions based on predefined patterns."""
        for group_name, patterns in corrective_actions.items():
            for pattern, suggestion in patterns.items():
                if re.search(pattern, error_message, re.IGNORECASE):
                    return group_name, suggestion
        return None, "No specific corrective action available."

    def load_corrective_actions(self, user_id):
        """
        Load corrective actions from the database for a specific user.
        Args:
            user_id (int): The ID of the user whose corrective actions to load.
        Returns:
            dict: Corrective actions organized by category.
        """
        corrective_actions = defaultdict(dict)
        try:
            training_data = TrainingData.query.filter_by(user_id=user_id).all()

            # Organize data into a dictionary grouped by category
            for data in training_data:
                corrective_actions[data.category][data.pattern] = data.suggestion

        except Exception as e:
            current_app.logger.error(f"Error loading corrective actions from database: {e}")
            raise ValueError("Error loading corrective actions from the database.")

        return corrective_actions


    def display_corrective_actions_from_file(self, file_path, training_data, user_id, log_dir):
        """
        Analyze failures from a file and provide corrective actions from the database.
        Args:
            file_path (str): Path to the log file containing failure messages.
            user_id (int): The ID of the user whose corrective actions to use.
        Returns:
            str: Message indicating unmatched errors if any.
        """
        corrective_actions = self.load_corrective_actions(training_data, user_id)
        suggestions_file_path = os.path.join(log_dir, "robot_failure_suggestions.txt")

        error_summary = defaultdict(lambda: {"count": 0, "suggestion": "", "unique_messages": {}})
        unmatched_errors = []
        unmatched_count = 0

        # Patterns to identify lines to skip, including [TestCase Description]
        skip_patterns = [
            re.compile(r"^--------.*_failure_log\.txt --------$"),
            re.compile(r"^=> .* encountered the following failures:$"),
            re.compile(r"^=> General Failures:$"),  # Treat "=> General Failures" as metadata
            re.compile(r"^$"),  # Empty lines
            re.compile(r"^\[TestCase Description\].*$", re.DOTALL)  # Skip [TestCase Description] lines
        ]

        def is_skip_line(line):
            """Check if a line matches any skip patterns."""
            return any(pattern.match(line) for pattern in skip_patterns)

        try:
            with open(file_path, 'r') as log_file, open(suggestions_file_path, 'w') as suggestions_file:
                for line in log_file:
                    line = line.strip()

                    # Skip lines that match the skip patterns
                    if is_skip_line(line):
                        continue

                    # Use suggest_corrective_action for each error line
                    group_name, suggestion = self.suggest_corrective_action(line, corrective_actions)

                    if group_name:
                        # Only count unique error messages
                        if line not in error_summary[(group_name, suggestion)]["unique_messages"]:
                            error_summary[(group_name, suggestion)]["unique_messages"][line] = 1
                        else:
                            error_summary[(group_name, suggestion)]["unique_messages"][line] += 1
                        error_summary[(group_name, suggestion)]["suggestion"] = suggestion
                    else:
                        unmatched_errors.append(line)
                        unmatched_count += 1

                # Write results for matched errors
                for (group, suggestion), details in error_summary.items():
                    count = sum(details["unique_messages"].values())
                    suggestions_file.write(f"Failure Group: {group}\n")
                    suggestions_file.write(f"Occurrences: {count}\n")
                    suggestions_file.write("Failures:\n")
                    for msg, occurrence in details["unique_messages"].items():
                        suggestions_file.write(f" - {msg} (Occurred {occurrence} times)\n")
                    suggestions_file.write(f"Suggested Action: {suggestion}\n")
                    suggestions_file.write(f"{'-' * 50}\n")

                # Write unmatched errors if any
                if unmatched_errors:
                    suggestions_file.write("\n******** Unmatched Errors **********\n")
                    for error in unmatched_errors:
                        suggestions_file.write(f"No corrective action found for error: {error}\n")

            print(f"Suggestions saved in '{suggestions_file_path}'.")

            if unmatched_count > 0:
                unmatched_message = f"==> No specific corrective actions found for {unmatched_count} errors. Training required!"
                print(unmatched_message)
                return unmatched_message

            return None

        except FileNotFoundError:
            raise ValueError(f"File {file_path} not found.")

    def load_corrective_actions(self, training_data,user_id):
        """
        Load corrective actions from the provided training data.
        Args:
            training_data (list): List of TrainingData objects.
        Returns:
            dict: Corrective actions organized by category.
        """
        corrective_actions = defaultdict(dict)
        for data in training_data:
            corrective_actions[data.category][data.pattern] = data.suggestion
        return corrective_actions

    def process_uploaded_file(self, file, username, name_suggestions=False):
        if not self.allowed_file(file.filename):
            raise ValueError("Unsupported file type")
        file_path = self.save_file(file, username)
        file_path = self.handle_gz_file(file_path)
        with open(file_path, "r") as f:
            xml_content = f.read()

        os.remove(file_path)

        failures = self.parse_robot_xml(xml_content=xml_content)
        if name_suggestions:
            display_corrective_actions_from_file(file_path)
        return failures



def load_and_render_template(template_name, context):
    """
    Load and render a Jinja2 template from the /templates/ConfigTemplates directory.

    :param template_name: Name of the Jinja2 template file (e.g., 'vxlan_config_template.j2')
    :param context: Dictionary containing context variables to pass to the template
    :return: Rendered template as a string
    """
    # Get the base directory of the project
    base_dir = os.path.abspath(os.path.dirname(__file__))

    # Define the path to the ConfigTemplates folder
    templates_dir = os.path.join(base_dir, 'templates', 'ConfigTemplates')

    # Initialize the Jinja2 environment with the FileSystemLoader
    env = Environment(loader=FileSystemLoader(templates_dir))

    # Load the specified template by name
    template = env.get_template(template_name)

    # Render the template with the provided context
    return template.render(context)
class BuildLLDPConnectionClass:
    def __init__(self, hostname,device_in_database):
        """
        Initialize with the hostname of the device.
        """
        self.hostname = hostname
        self.device_list=device_in_database



    def get_lldp_neighbors(self,dev):
        """
        Fetches the LLDP neighbors for the given device and filters based on the remote system name in device_list.
        """
        neighbors_dict = {}
        device_list=self.device_list
        # Simplify device names in device_list by removing domain suffix
        simplified_device_list = [device.split('.')[0] if '.' in device else device for device in device_list]

        try:
            # Fetch LLDP neighbors information
            neighbors = dev.rpc.get_lldp_neighbors_information()
            # Print the XML output for debugging
            # print(etree.tostring(neighbors, pretty_print=True).decode('utf-8'))
            # Parse the XML to populate the neighbors dictionary
            for neighbor in neighbors.findall('.//lldp-neighbor-information'):
                interface_element = neighbor.find('lldp-local-port-id')
                remote_system_element = neighbor.find('lldp-remote-system-name')
                remote_port_desc_element = neighbor.find('lldp-remote-port-description')
                remote_port_id_element = neighbor.find('lldp-remote-port-id')

                # Extract values and handle missing elements
                interface = interface_element.text.strip() if interface_element is not None else 'Unknown'
                remote_system_name = remote_system_element.text.strip() if remote_system_element is not None else 'Unknown'
                remote_port_desc = remote_port_desc_element.text.strip() if remote_port_desc_element is not None else None
                remote_port_id = remote_port_id_element.text.strip() if remote_port_id_element is not None else None

                # Simplify the remote system name by removing domain suffix
                simplified_remote_system_name = remote_system_name.split('.')[
                    0] if '.' in remote_system_name else remote_system_name

                # Ensure valid port description
                sanitized_port_desc = remote_port_desc or remote_port_id or 'Unknown'
                if simplified_remote_system_name in [d.split('.')[0] for d in self.device_list]:
                    if self.hostname not in neighbors_dict:
                        neighbors_dict[self.hostname] = []
                    neighbors_dict[self.hostname].append((remote_system_name, interface, sanitized_port_desc))
                    #print(f"Added neighbor - System: {remote_system_name}, Interface: {interface}, Port Desc: {sanitized_port_desc}")
        except Exception as e:
            logging.warning(f"Failed to fetch LLDP neighbors: {e}")
            raise
        logging.info(f"neighbors_dict: {neighbors_dict}")
        return neighbors_dict

    def sanitize_port_desc(self, remote_system_name, local_interface, port_desc):
        """
        Sanitize and validate the LLDP port description.
        """
        if not self.is_valid_port_desc(port_desc):
            logging.warning(f"Invalid port description: '{port_desc}' on device '{remote_system_name}', local interface '{local_interface}'.")
            return None
        return port_desc

    def is_valid_port_desc(self, port_desc):
        """
        Validate the port description based on a regular expression.
        """
        interface_pattern = r"^(et|ge|xe|em|re|fxp)\-[0-9]+\/[0-9]+\/[0-9]+(:[0-9]+)?$"
        return bool(re.match(interface_pattern, port_desc))
    @staticmethod
    def simplify_neighbors_dict(neighbors_dict):
        """
        Removes the domain suffix from the neighbor hostnames, but not from IP keys.
        """
        simplified_dict = {}
        for key, neighbors in neighbors_dict.items():
            simplified_neighbors = [(neighbor[0].split('.')[0], neighbor[1], neighbor[2]) for neighbor in neighbors]
            simplified_dict[key] = simplified_neighbors  # Keep the original key (IP) unchanged
        #print(simplified_dict)
        return simplified_dict

    @staticmethod
    def build_connections(trim_domain_neighbors):
        """
        Build a connection dictionary from the LLDP neighbors.
        """
        connections = []
        for key, values in trim_domain_neighbors.items():
            for value in values:
                connection = {
                    key: value[1],  # Local device and interface
                    value[0]: value[2]  # Remote device and port description
                }
                connections.append(connection)
        return connections


class OnboardDeviceClass:
    def __init__(self, socketio, stop_events, Installerrors, image_md5):
        self.socketio = socketio
        self.stop_events = stop_events
        self.Installerrors = Installerrors
        self.image_md5 = image_md5

    @staticmethod
    def calculate_md5(file_path):
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def get_remote_md5(self, dev, remote_path,local_image_md5):
        try:
            logging.info(f"Checking if file exists on remote device: {remote_path}")
            response = dev.rpc.get_checksum_information(path=remote_path)
            response_str = etree.tostring(response, pretty_print=True).decode()
            logging.info(f"Full get_checksum_information Response: {response_str}")
            checksum_output = response.findtext('.//checksum')
            if checksum_output:
                checksum_output = checksum_output.strip()  # Strip any whitespace
                logging.info(f"Remote MD5 checksum: {checksum_output}")
                if checksum_output == local_image_md5:
                    return True
            else:
                logging.error("MD5 checksum not found in the response.")
        except RpcError as e:
            if "No such file or directory" in str(e):
                logging.error(f"File not found on remote device: {remote_path}. Proceeding to copy the file.")
                print(f"File not found on remote device: {remote_path}. Proceeding to copy the file.")
                # If the file does not exist, return None to indicate the need for a copy
                return None
            else:
                logging.error(f"get_checksum_information RPC failed: {str(e)}")
        except Exception as e:
            logging.error(f"Unexpected error occurred: {str(e)}")
        return None



    def check_storage_space(self, dev, required_space):
        try:
            storage_info = dev.rpc.get_system_storage()
            max_available_space = 0
            selected_mount_point = '/var/tmp'  # Always use /var/tmp as the mount point
            for filesystem in storage_info.xpath('//filesystem'):
                mounted_on = filesystem.findtext('mounted-on')
                avail_blocks = filesystem.findtext('available-blocks')
                # Only check storage for /var/tmp
                if avail_blocks and '/var' in mounted_on:
                    avail_bytes = int(avail_blocks) * 1024  # Convert blocks to bytes
                    logging.info(f"Device {dev.hostname} - {mounted_on}: available space {avail_bytes} bytes")
                    # Compare available space for /var/tmp and log the selection
                    max_available_space = avail_bytes
                    logging.info(f"Selected mount point for Image: {dev.hostname}: {selected_mount_point}")

            # Ensure that the available space is sufficient
            if max_available_space >= required_space:
                return True, max_available_space, selected_mount_point
            else:
                return False, max_available_space, selected_mount_point
        except Exception as e:
            logging.error(f"Error checking storage space: {str(e)}")
            return False, None, None

    def install_image_on_device(self, dev, remote_image_path):
        try:
            sw = SW(dev)
            logging.info(f"Remote Image path: {dev.hostname}, {remote_image_path}")
            ok, msg = sw.install(package=remote_image_path, validate=True, progress=self.myprogress, dev_timeout=2400,
                                 checksum_timeout=400, no_copy=True)
            if ok:
                logging.info('Image installed on %s successfully.', dev.hostname)
                sw.reboot()
                return True
            else:
                logging.error('Failed to install image on %s: %s', dev.hostname, msg)
                return False
        except Exception as e:
            logging.error('Error installing image on %s: %s', dev.hostname, str(e))
            return False


    def scp_progress(self, filename, size, sent, device_id):
        # Calculate progress as a percentage
        progress = int((sent / size) * 100)
        # Emit progress incrementally during the copy
        self.socketio.emit('copy_progress', {'device_id': device_id, 'progress': progress, 'stage': 'copying'})




def is_reachable(ip):
    try:
        socket.gethostbyname(ip)
        return True
    except socket.error:
        return False

def get_router_details_from_db():
    router_details = []
    from app.models import DeviceInfo  # Import here to avoid circular imports
    #devices = DeviceInfo.query.all()
    devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
    for device in devices:
        router_details.append({
            'hostname': device.hostname,
            'ip': device.ip,
            'username': device.username,
            'password': device.password
        })
    return router_details

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have the necessary permissions to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def create_user_folders(username):
    user_folder = os.path.join('uploads', username)
    os.makedirs(user_folder, exist_ok=True)
    log_folder = os.path.join('logs', username)
    os.makedirs(log_folder, exist_ok=True)
    telemetry_folder=os.path.join('telemetry', username)
    os.makedirs(telemetry_folder, exist_ok=True)
    return user_folder, log_folder , telemetry_folder


def setup_user_logging(log_folder):
    # Define the log file path
    log_file_path = os.path.join(log_folder, 'debug.log')
    # Set up a rotating file handler
    handler = RotatingFileHandler(log_file_path, maxBytes=1000000, backupCount=1)
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    # Get the root logger and configure it
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    # Remove any existing handlers
    if logger.hasHandlers():
        logger.handlers.clear()
    # Add the new handler
    logger.addHandler(handler)
    logging.info(f"Logging set up at {log_file_path}")
    return logger



def transfer_file_to_router(config_lines, router_ip, router_user, router_password, device_name, config_format):
    cu = None
    dev = None

    def emit_progress(router_ip, progress, stage, error=None):
        message = {'ip': router_ip, 'progress': progress, 'stage': stage}
        if error:
            message['error'] = error
        logging.info(f"Emitting progress: {message}")
        socketio.emit('progress', message)

    try:
        logging.info(f"Attempting to connect to {device_name} using DeviceConnectorClass.")
        emit_progress(router_ip, 0, 'Connecting')

        # Use DeviceConnectorClass to establish the connection
        device_connector = DeviceConnectorClass(hostname=device_name, ip=router_ip, username=router_user,
                                                password=router_password)
        dev = device_connector.connect_to_device()
        if not dev:
            raise ConnectionError(f"Unable to connect to {device_name} using hostname or IP.")

        logging.info(f"Connection established to {device_name}")
        emit_progress(router_ip, 25, 'Connected')
        cu = Config(dev)

        # Lock the configuration
        cu.lock()
        logging.info("Configuration locked for editing.")
        emit_progress(router_ip, 50, 'Locked configuration')

        # Prepare and load configuration
        if isinstance(config_lines, str):
            config_lines = config_lines.split('\n')
        elif not isinstance(config_lines, list):
            raise ValueError("config_lines should be a list of strings")
        clean_config_lines = [line for line in config_lines if not line.startswith("##")]
        config_to_load = "\n".join(clean_config_lines)
        cu.load(config_to_load, format=config_format, ignore_warning=True)
        emit_progress(router_ip, 75, 'Loaded configuration')

        # Commit the configuration
        cu.commit()
        logging.info("Configuration committed successfully.")
        emit_progress(router_ip, 100, 'Completed')

        return f"** Configuration loaded successfully on {device_name} **"
    except (LockError, UnlockError) as lock_error:
        logging.error(f"LockError on {router_ip}: {str(lock_error)}")
        emit_progress(router_ip, 0, 'Error', str(lock_error))
        return f"** Error..!! {str(lock_error)} on {device_name} **"
    except ConnectAuthError as e:
        logging.error(f"Connection authentication error for device {router_ip}: {str(e)}")
        return {"device": router_ip, "message": str(e)}
    except ConnectError as e:
        logging.error(f"Connection error for device {router_ip}: {str(e)}")
        return {"device": router_ip, "message": str(e)}
    except Exception as e:
        logging.error(f"Error loading configuration on {router_ip}: {str(e)}")
        emit_progress(router_ip, 0, 'Error', str(e))
        if cu:
            try:
                cu.rollback()
                cu.commit()
                cu.unlock()
                logging.info("Configuration rollback successfully.")
                return f"** Error..!! {str(e)} Rolled back configuration on {device_name} **"
            except Exception as rollback_error:
                logging.error(f"Error during rollback: {str(rollback_error)}")
                return f"** Error..!! {str(e)} Rollback failed on {device_name}: {str(rollback_error)} **"
        return f"** Error..!! {str(e)} on {device_name} **"
    finally:
        if dev:
            device_connector.close_connection(dev)



def get_router_ips_from_csv(file_path):
    router_ips = []
    if os.path.exists(file_path):
        with open(file_path, 'r') as csvfile:
            csvreader = csv.DictReader(csvfile)
            for row in csvreader:
                router_ips.append(row['ip'])
    return router_ips
def get_router_details_from_csv(file_path):
    router_details = []
    if os.path.exists(file_path):
        with open(file_path, 'r') as csvfile:
            csvreader = csv.DictReader(csvfile)
            for row in csvreader:
                router_details.append(row)
    return router_details
def get_lldp_neighbors(dev):
    lldp_info = dev.rpc.get_lldp_neighbors_information()
    neighbors = []
    for neighbor in lldp_info.findall('.//lldp-neighbor-information'):
        local_int = neighbor.find('lldp-local-port-id').text.strip()
        remote_system_name = neighbor.find('lldp-remote-system-name').text.strip()
        remote_port_desc = neighbor.find('lldp-remote-port-description').text.strip()
        neighbors.append({'local_int': local_int, 'remote_system_name': remote_system_name, 'remote_port_desc': remote_port_desc})
    return neighbors
def get_next_available_ip():
    import ipaddress
    # Initialize the IP pool
    base_ip = ipaddress.IPv4Address('192.168.1.0')
    ip_pool = (base_ip + i for i in range(1, 254))  # Use a generator

    # Track used IPs
    used_ips = set()

    def _get_ip():
        for ip in ip_pool:
            if ip not in used_ips:
                used_ips.add(ip)
                return str(ip)
        return None  # No more available IPs

    return _get_ip

# Ensure the function is defined
get_next_available_ip = get_next_available_ip()


def fetch_lldp_neighbors_and_sanitize(dev, retries=5, wait_time=30):
    # Helper function to validate port descriptions
    def is_valid_port_desc(port_desc):
        # Valid interface patterns (modify as per your environment)
        interface_pattern = r"^(et|ge|xe|em|re|fxp)\-[0-9]+\/[0-9]+\/[0-9]+(:[0-9]+)?$"
        return bool(re.match(interface_pattern, port_desc))

    # Function to clean up invalid port descriptions and log detailed information
    def sanitize_port_desc(remote_system_name, local_interface, port_desc):
        if not is_valid_port_desc(port_desc):
            logging.warning(
                f"Invalid port description: '{port_desc}' on device '{remote_system_name}', local interface '{local_interface}'. Waiting for LLDP update.")
            return None  # Indicate invalid description
        return port_desc
    neighbors_dict = defaultdict(list)
    for _ in range(retries):
        neighbors = dev.rpc.get_lldp_neighbors_information()
        updated = False
        for neighbor in neighbors.findall('.//lldp-neighbor-information'):
            interface = neighbor.find('lldp-local-port-id').text.strip()  # Local interface
            remote_system_name = neighbor.find('lldp-remote-system-name').text.strip()  # Remote system name
            remote_port_desc = neighbor.find(
                'lldp-remote-port-description').text.strip()  # Remote interface description

            # Sanitize port description and log invalid cases with more detail
            sanitized_port_desc = sanitize_port_desc(remote_system_name, interface, remote_port_desc)

            if sanitized_port_desc:  # Only include valid descriptions
                neighbors_dict[dev.hostname].append((remote_system_name, interface, sanitized_port_desc))
                updated = True
            else:
                logging.warning(
                    f"Skipping interface '{interface}' on device '{remote_system_name}' due to invalid port description.")

        if updated:
            logging.info(f"LLDP data updated and valid: {neighbors_dict}")
            return neighbors_dict  # Return as soon as valid data is available

        logging.warning(f"Waiting for valid LLDP neighbor updates... Retrying in {wait_time} seconds.")
        time.sleep(wait_time)  # Wait and retry

    logging.error(f"Failed to retrieve valid LLDP neighbor information after {retries} retries.")
    return neighbors_dict  # Return empty or partially populated dictionary

def generate_bgp_config(local_ip, neighbor_ip, local_as, remote_as):
    commands = []
    commands.extend([
        f"set protocols bgp group underlay neighbor {neighbor_ip} peer-as {remote_as}",
        f"set protocols bgp group underlay neighbor {neighbor_ip} local-address {local_ip}",
        f"set protocols bgp group underlay local-as {local_as}",
        f"set protocols bgp group underlay neighbor {neighbor_ip} family inet unicast"
    ])
    #logging.info(f"** generate_bgp_config: Commands: {commands}")
    return commands
def generate_common_config(ipv4=False, ipv6=False):
    common_config = []

    if ipv4:
        common_config.append("set protocols lldp interface all")
        common_config.append("set policy-options policy-statement export_v4_lo0 term 1 from interface lo0")
        common_config.append("set policy-options policy-statement export_v4_lo0 term 1 then accept")
        common_config.append("set protocols bgp group underlay_v4 export export_v4_lo0")
        common_config.append("set protocols bgp group underlay_v4 type external")

    if ipv6:
        common_config.append("set policy-options policy-statement export_v6_lo0 term 1 from interface lo0")
        common_config.append("set policy-options policy-statement export_v6_lo0 term 1 from rib inet6.0")
        common_config.append("set policy-options policy-statement export_v6_lo0 term 1 then accept")
        common_config.append("set protocols bgp group underlay_v6 export export_v6_lo0")
        common_config.append("set protocols bgp group underlay_v6 type external")
    return common_config


def generate_interface_config(interface, ip_address):
    return [
        "## Interface Config ##",
        f"delete interfaces {interface}",
        f"set interfaces {interface} unit 0 family inet address {ip_address}/30"
    ]


def generate_config(
    commands,
    connections,
    local_as_mapping,
    delete_underlay_group,
    use_ipv4,
    use_ipv6,
    use_dlb=False,
    use_glb=False,
    use_slb=False,
    ip_assignments=None,
    base_ips=None,
):
    # Initialize variables
    ip_assignments = ip_assignments or {}
    ipv4_network = None
    ipv6_network = None
    allocated_ipv6_addresses = set()
    base_ips = base_ips or "192.168.1.0/24,fd00:1::/64"

    # Parse base IPs
    try:
        base_ip_list = base_ips.split(",")
        for base_ip in base_ip_list:
            network = ipaddress.ip_network(base_ip.strip(), strict=False)
            if isinstance(network, ipaddress.IPv4Network):
                ipv4_network = network
            elif isinstance(network, ipaddress.IPv6Network):
                ipv6_network = network
    except ValueError as e:
        logging.error(f"Invalid base IPs provided: {base_ips}. Error: {e}")
        raise

    def get_ip(subnet_counter, host_id, ipv6=False):
        """Generate unique IP addresses."""
        try:
            if ipv6:
                base_address = int(ipv6_network.network_address)
                ipv6_address = ipaddress.IPv6Address(base_address + (subnet_counter * (2**64)) + host_id)
                if ipv6_address in allocated_ipv6_addresses:
                    raise ValueError(f"Duplicate IPv6 address allocation detected: {ipv6_address}")
                allocated_ipv6_addresses.add(ipv6_address)
                return str(ipv6_address)
            else:
                base_octets = str(ipv4_network.network_address).split(".")[:2]
                third_octet = subnet_counter % 256
                second_octet = subnet_counter // 256
                return f"{base_octets[0]}.{base_octets[1]}.{third_octet}.{host_id}"
        except ValueError as e:
            logging.error(f"Error generating IP address: {e}")
            raise

    def generate_bgp_neighbor_config(local_ip, neighbor_ip, local_as, remote_as, group_name):
        """Generate BGP neighbor configuration."""
        return [
            f"set protocols bgp group {group_name} neighbor {neighbor_ip} peer-as {remote_as}",
            f"set protocols bgp group {group_name} neighbor {neighbor_ip} local-address {local_ip}",
            f"set protocols bgp group {group_name} local-as {local_as}",
        ]

    def append_unique_command(command_list, command):
        """Append a command to the list only if it doesn't already exist."""
        if command not in command_list:
            command_list.append(command)

    def append_special_config(command_list, use_dlb, use_glb, use_slb):
        """Append special configurations based on flags."""
        if use_dlb:
            append_unique_command(command_list, "set groups global forwarding-options enhanced-hash-key ecmp-dlb flowlet")
        if use_glb:
            for glb_command in [
                "set protocols bgp global-load-balancing load-balancer-only",
                "set protocols bgp global-load-balancing helper-only",
            ]:
                append_unique_command(command_list, glb_command)
        if use_slb:
            for slb_command in [
                "set policy-options policy-statement ecmp then load-balance per-packet",
                "set routing-options forwarding-table export ecmp",
            ]:
                append_unique_command(command_list, slb_command)

    # Process connections
    ipv4_subnet_counter = 0
    ipv6_subnet_counter = 0
    for connection in connections:
        neighbor_ip_mapping = {}
        host_id = 1
        for device, interface in connection.items():
            # Ensure commands[device] is initialized as a list
            if device not in commands:
                commands[device] = []

            if delete_underlay_group:
                append_unique_command(commands[device], "delete protocols bgp group underlay_v4")
                append_unique_command(commands[device], "delete protocols bgp group underlay_v6")

            ipv4_address = ipv6_address = None

            if use_ipv4:
                ipv4_address = get_ip(ipv4_subnet_counter, host_id, ipv6=False)
                neighbor_ip_mapping[f"{device}-{interface}-ipv4"] = ipv4_address
                append_unique_command(commands[device], f"set interfaces {interface} unit 0 family inet address {ipv4_address}/30")
            if use_ipv6:
                ipv6_address = get_ip(ipv6_subnet_counter, host_id, ipv6=True)
                neighbor_ip_mapping[f"{device}-{interface}-ipv6"] = ipv6_address
                append_unique_command(commands[device], f"set interfaces {interface} unit 0 family inet6 address {ipv6_address}/64")

            host_id += 1

        # Handle BGP neighbor configuration
        for device, interface in connection.items():
            for ip_version in ["ipv4", "ipv6"]:
                if f"{device}-{interface}-{ip_version}" not in neighbor_ip_mapping:
                    continue
                local_ip = neighbor_ip_mapping[f"{device}-{interface}-{ip_version}"]
                local_as = local_as_mapping.get(device)

                for remote_device, remote_interface in connection.items():
                    if remote_device == device:
                        continue  # Skip self
                    if f"{remote_device}-{remote_interface}-{ip_version}" not in neighbor_ip_mapping:
                        continue
                    remote_ip = neighbor_ip_mapping[f"{remote_device}-{remote_interface}-{ip_version}"]
                    remote_as = local_as_mapping.get(remote_device)

                    # Ensure local IP is not treated as its own neighbor
                    if remote_ip == local_ip:
                        continue

                    if local_as and remote_as:
                        group_name = "underlay_v4" if ip_version == "ipv4" else "underlay_v6"
                        for bgp_command in generate_bgp_neighbor_config(local_ip, remote_ip, local_as, remote_as, group_name):
                            append_unique_command(commands[device], bgp_command)

        ipv4_subnet_counter += use_ipv4
        ipv6_subnet_counter += use_ipv6

    # Append special configurations
    for device, command_list in commands.items():
        append_special_config(command_list, use_dlb, use_glb, use_slb)



class DeviceHealthCheck:
    @staticmethod
    def remove_none_values(d):
        """Recursively remove None values from dictionaries or lists."""
        if isinstance(d, dict):
            return {k: DeviceHealthCheck.remove_none_values(v) for k, v in d.items() if v is not None}
        elif isinstance(d, list):
            return [DeviceHealthCheck.remove_none_values(item) for item in d if item is not None]
        else:
            return d
    @staticmethod
    def is_valid_hostname(hostname):
        """Check if a hostname can be resolved."""
        try:
            socket.gethostbyname(hostname)
            return True
        except socket.error as e:
            logging.error(f"Failed to resolve hostname {hostname}: {e}")
            return False
    @staticmethod
    def establish_connection(hostname, ip, username, password, port=22, timeout=10, retries=3, retry_delay=5):
        last_error = None
        for attempt in range(retries):
            try:
                if hostname and DeviceHealthCheck.is_valid_hostname(hostname):
                    logging.info(f"Attempting connection to {hostname} using hostname (Attempt {attempt + 1}).")
                    dev = Device(
                        host=hostname,
                        user=username,
                        passwd=password,
                        port=port,
                        timeout=timeout
                    )
                    dev.open()
                    logging.info(f"Successfully connected to {hostname} using hostname.")
                    return dev, None

                if ip:
                    logging.warning(f"Invalid hostname {hostname}. Attempting connection to IP {ip} (Attempt {attempt + 1}).")
                    dev = Device(
                        host=ip,
                        user=username,
                        passwd=password,
                        port=port,
                        timeout=timeout
                    )
                    dev.open()
                    logging.info(f"Successfully connected to {ip} using IP.")
                    return dev, None
                else:
                    raise ValueError("Both hostname and IP are invalid or missing.")

            except (ConnectError, paramiko.SSHException, EOFError) as e:
                last_error = f"{e.__class__.__name__}: {str(e)}"
                logging.error(f"Connection attempt {attempt + 1} failed for {hostname or ip}. Last error: {last_error}")
                if attempt < retries - 1:
                    logging.info(f"Retrying connection in {retry_delay} seconds...")
                    time.sleep(retry_delay)

            except Exception as e:
                last_error = f"{e.__class__.__name__}: {str(e)}"
                logging.error(f"Unexpected error during connection attempt {attempt + 1}: {last_error}")
                break

        error_message = f"All {retries} attempts to connect to {hostname or ip} failed. Last error: {last_error}"
        logging.error(error_message)
        return None, error_message


    @staticmethod
    def get_interface_status(device, interface_name):
        try:
            interface_info = device.rpc.get_interface_information(terse=True, interface_name=interface_name)
            physical_interfaces = interface_info.findall('.//physical-interface')
            for interface in physical_interfaces:
                name = interface.find('name').text.strip()
                if name == interface_name:
                    oper_status = interface.find('oper-status').text.strip().lower()
                    return oper_status == "up"

            logging.error(f"Interface {interface_name} not found in RPC response.")
            return False

        except Exception as e:
            logging.error(f"Error retrieving RPC interface status for {interface_name}: {e}")
            return False

    @staticmethod
    def process_edge(router_details_dict, edge):
        try:
            if not isinstance(edge, dict) or "data" not in edge:
                return edge.get("data", {}).get("id", "Unknown"), "Invalid edge: Missing 'data' key"

            edge_data = edge["data"]
            source = edge_data.get("source")
            target = edge_data.get("target")
            label = edge_data.get("label", "")
            edge_id = edge_data.get("id", f"{source}--{target}")

            if "--" in label:
                source_interface, target_interface = label.split("--")
            else:
                return edge_id, "Invalid edge: Cannot extract interfaces from label"

            if not source or not target:
                return edge_id, "Invalid edge: Missing source or target"
            if not source_interface or not target_interface:
                return edge_id, "Invalid edge: Missing source_interface or target_interface"

            if source not in router_details_dict:
                return edge_id, f"Source '{source}' not found in router details."
            if target not in router_details_dict:
                return edge_id, f"Target '{target}' not found in router details."

            source_router = router_details_dict[source]
            target_router = router_details_dict[target]

            logging.info("Establishing connection with source device...")
            source_dev, source_error = DeviceHealthCheck.establish_connection(
                hostname=source_router.get("hostname"),
                ip=source_router.get("ip"),
                username=source_router.get("username"),
                password=source_router.get("password"),
            )
            if not source_dev:
                return edge_id, f"Source connection error: {source_error}"

            logging.info("Establishing connection with target device...")
            target_dev, target_error = DeviceHealthCheck.establish_connection(
                hostname=target_router.get("hostname"),
                ip=target_router.get("ip"),
                username=target_router.get("username"),
                password=target_router.get("password"),
            )
            if not target_dev:
                source_dev.close()
                return edge_id, f"Target connection error: {target_error}"

            source_interface_status = DeviceHealthCheck.get_interface_status(source_dev, source_interface)
            target_interface_status = DeviceHealthCheck.get_interface_status(target_dev, target_interface)

            logging.info(f"Source interface {source_interface} status: {source_interface_status}")
            logging.info(f"Target interface {target_interface} status: {target_interface_status}")

            source_dev.close()
            target_dev.close()

            if source_interface_status and target_interface_status:
                return edge_id, "Healthy"
            else:
                source_status = "up" if source_interface_status else "down"
                target_status = "up" if target_interface_status else "down"
                return edge_id, f"Source interface: {source_status}, Target interface: {target_status}"

        except Exception as e:
            logging.error(f"Error processing edge {edge}: {e}", exc_info=True)
            return edge.get("data", {}).get("id", "Unknown"), f"Error: {str(e)}"

    @staticmethod
    def batch_edges(edges, batch_size=50):
        for i in range(0, len(edges), batch_size):
            yield edges[i:i + batch_size]

    @staticmethod
    def check_link_health(router_details, edges):
        router_details_dict = {router["hostname"]: router for router in router_details if "hostname" in router}
        link_health_status = {}
        with ThreadPoolExecutor() as executor:
            futures = []
            for batch in DeviceHealthCheck.batch_edges(edges, batch_size=50):
                for edge in batch:
                    futures.append(executor.submit(DeviceHealthCheck.process_edge, router_details_dict, edge))

            for future in as_completed(futures):
                edge_id, status = future.result()
                link_health_status[edge_id] = status

        return link_health_status

    @staticmethod
    def preprocess_router_details(router_details):
        if isinstance(router_details, list):
            return {router['hostname']: router for router in router_details if 'hostname' in router}
        return router_details

    @staticmethod
    def check_device_health(router_details, devices):
        logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)
        router_details = DeviceHealthCheck.preprocess_router_details(router_details)

        device_health_status = {}

        for device in devices:
            device_id = device.get('id')
            if not device_id:
                logging.warning("Device ID is missing in request.")
                continue

            device_info = router_details.get(device_id)
            if not device_info:
                logging.warning(f"No details found for device: {device_id}")
                device_health_status[device_id] = "unreachable"
                continue

            hostname = device_info.get('hostname', device_id)
            port = 22

            try:
                logging.info(f"Initiating SSH handshake to {hostname}.")
                transport = paramiko.Transport((hostname, port))
                transport.start_client()

                if transport.get_remote_server_key():
                    logging.info(f"SSH handshake to {hostname} succeeded.")
                    device_health_status[device_id] = "reachable"
                else:
                    logging.warning(f"SSH handshake to {hostname} failed (no server key).")
                    device_health_status[device_id] = "unreachable"

            except paramiko.SSHException as e:
                logging.error(f"SSH handshake failed for device {device_id} ({hostname}): {e}")
                device_health_status[device_id] = "unreachable"
            except ConnectionResetError as e:
                logging.error(f"Connection reset by peer for device {device_id} ({hostname}): {e}")
                device_health_status[device_id] = "unreachable"
            except TimeoutError as e:
                logging.error(f"Timeout error for device {device_id} ({hostname}): {e}")
                device_health_status[device_id] = "unreachable"
            except socket.gaierror as e:
                logging.error(f"❌ DNS resolution error for {device_id} ({hostname}): {e}")
                device_health_status[device_id] = "unreachable"
            except Exception as e:
                logging.error(f"Unexpected error for device {device_id} ({hostname}): {e}", exc_info=True)
                device_health_status[device_id] = "unreachable"

            finally:
                try:
                    transport.close()
                except NameError:
                    pass

        return device_health_status

def generate_bgp_scale_config(initial_local_as, initial_peer_as, neighbor_count, as_type,
                              bgp_neighbor_ip_parts, bgp_versions, bgp_type, bgp_interface_name):
    config_lines = []
    # Add policy-options statements once
    config_lines.append(f"set policy-options policy-statement export-policy term 1 from interface lo0.0")
    config_lines.append(f"set policy-options policy-statement export-policy term 1 then accept")

    config_lines.append(f"set routing-options autonomous-system {initial_local_as} ")
    for bgp_version in bgp_versions:
        if bgp_type == "ibgp":
            config_lines.append(f"set protocols bgp group internal family {bgp_version} unicast")
        elif bgp_type == "ebgp":
            config_lines.append(f"set protocols bgp group external family {bgp_version} unicast")
    if bgp_type == "ibgp":
        config_lines.append(f"set protocols bgp group internal type internal")
        config_lines.append(f"set protocols bgp group internal multipath ")
        config_lines.append(f"set protocols bgp group internal export export-policy")
    elif bgp_type == "ebgp":
        config_lines.append(f"set protocols bgp group external type external")
        config_lines.append(f"set protocols bgp group external multipath ")
        config_lines.append(f"set protocols bgp group external export export-policy")
    if bgp_interface_name:
        config_lines.append(f"set interfaces {bgp_interface_name} vlan-tagging")
    interface_sequence = 1

    for version in bgp_versions:
        if version == 'ipv4' and 'ipv4' in bgp_neighbor_ip_parts:
            ip_parts = list(map(int, bgp_neighbor_ip_parts['ipv4'].split('.')))
            for i in range(neighbor_count):
                if ip_parts[2] == 254:
                    ip_parts[1] += 1
                    ip_parts[2] = 0
                else:
                    ip_parts[2] += 1
                neighbor_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{ip_parts[3]}"
                interface_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{ip_parts[3] + 1}/30"
                current_local_as = initial_local_as if as_type == 'global' else initial_local_as + i
                current_peer_as = initial_peer_as + i
                if bgp_type == "ibgp":
                    config_lines.append(f"set protocols bgp group internal neighbor {neighbor_ip}")
                elif bgp_type == "ebgp":
                    config_lines.append(
                        f"set protocols bgp group external neighbor {neighbor_ip} peer-as {current_peer_as}")
                    config_lines.append(
                        f"set protocols bgp group external neighbor {neighbor_ip} local-as {current_local_as}")
                # Add line for interface configuration
                if bgp_interface_name:
                    config_lines.append(
                        f"set interfaces {bgp_interface_name}.{interface_sequence} family inet address {interface_ip}")
                    config_lines.append(
                        f"set interfaces {bgp_interface_name}.{interface_sequence} vlan-id {interface_sequence}")
                interface_sequence += 1

        if version == 'ipv6' and 'ipv6' in bgp_neighbor_ip_parts:
            interface_sequence = 1
            ip_parts = bgp_neighbor_ip_parts['ipv6'].split(':')
            for i in range(neighbor_count):
                last_segment = int(ip_parts[2], 16)
                last_segment += 1
                ip_parts[2] = hex(last_segment)[2:]
                neighbor_ip = ':'.join(ip_parts)
                interface_ip = f"{neighbor_ip[:-1]}2/64"
                neighbor_ip = f"{neighbor_ip[:-1]}1"
                current_local_as = initial_local_as if as_type == 'global' else initial_local_as + i
                current_peer_as = initial_peer_as + i
                if bgp_type == "ibgp":
                    config_lines.append(f"set protocols bgp group internal neighbor {neighbor_ip}")
                elif bgp_type == "ebgp":
                    config_lines.append(
                        f"set protocols bgp group external neighbor {neighbor_ip} peer-as {current_peer_as}")
                    config_lines.append(
                        f"set protocols bgp group external neighbor {neighbor_ip} local-as {current_local_as}")
                # Add line for interface configuration
                if bgp_interface_name:
                    config_lines.append(
                        f"set interfaces {bgp_interface_name}.{interface_sequence} family inet6 address {interface_ip}")
                    config_lines.append(
                        f"set interfaces {bgp_interface_name}.{interface_sequence} vlan-id {interface_sequence}")
                interface_sequence += 1
    return config_lines

class VxlanConfigGeneratorClass:
    def __init__(self, spine_ips, leaf_ips, base_ip_parts,base_ipv6_parts, last_octet, base_vxlan_vni, base_vxlan_vlan_id,
                 num_vxlan_configs, overlay_service_type, leaf_base_as, spine_base_as, service_count, service_int_leaves, esi_lag_services,spine_tags,leaf_tags,GenerateOverlayBtn_State,user_template=None):
        self.spine_ips = spine_ips
        self.leaf_ips = leaf_ips
        self.base_ip_parts = base_ip_parts
        self.base_ipv6_parts = base_ipv6_parts
        self.last_octet = last_octet
        self.base_vxlan_vni = base_vxlan_vni
        self.base_vxlan_vlan_id = base_vxlan_vlan_id
        self.num_vxlan_configs = num_vxlan_configs
        self.overlay_service_type = overlay_service_type
        self.leaf_base_as = leaf_base_as
        self.spine_base_as = spine_base_as
        self.service_count = service_count
        self.service_int_leaves = service_int_leaves
        self.esi_lag_services = esi_lag_services
        self.spine_tags=spine_tags
        self.leaf_tags=leaf_tags
        self.GenerateOverlayBtn_State=GenerateOverlayBtn_State
        self.user_template = user_template

    @classmethod
    def get_user_template_folder(cls, username):
        """
        Returns the user-specific template directory inside `templates/ConfigTemplates/<username>/`.
        Ensures the folder exists before returning.
        """
        base_dir = os.path.abspath(os.path.dirname(__file__))
        templates_dir = os.path.join(base_dir, 'templates', 'ConfigTemplates')
        user_folder = os.path.join(templates_dir, username)

        # ✅ Ensure the user template folder exists
        os.makedirs(user_folder, exist_ok=True)

        return user_folder
    def load_template(self, template_name):
        """
        Load a Jinja2 template from the templates/ConfigTemplates directory.
        """
        base_dir = os.path.abspath(os.path.dirname(__file__))
        templates_dir = os.path.join(base_dir, 'templates', 'ConfigTemplates')
        env = Environment(loader=FileSystemLoader(templates_dir))
        return env.get_template(template_name)

    def get_associated_leaves(self, spine_tag, leaf_tags):
        """
        This function returns the leaf tags that are associated with the given spine tag.
        It compares the spine tag with the leaf tags and returns a list of leaf tags that match the spine tag.
        """
        associated_leaves = [leaf_tag for leaf_tag in leaf_tags if leaf_tag == spine_tag]
        return associated_leaves



    def generate_spine_configs(self, spine_tags=None, leaf_tags=None):
        """
        Generate configurations for spine devices using the Jinja2 template.
        If overlay_service_type is 'vxlan_vlan_aware_t2_seamless_stitching', spine_tags and leaf_tags are required.
        """

        # Load the Jinja2 environment and template
        template_name = "spine_config_tmpl.j2"
        template = self.load_template(template_name)

        spine_configs = []
        overlay_as = self.spine_base_as  # Use the same AS for both spines and leaves

        # Default spine_tags and leaf_tags to ['tag1'] if not provided
        if spine_tags is None or len(spine_tags) == 0:
            spine_tags = ['tag1'] * len(self.spine_ips)  # Default to 'tag1' for all spines
        if leaf_tags is None or len(leaf_tags) == 0:
            leaf_tags = ['tag1'] * len(self.leaf_ips)  # Default to 'tag1' for all leaves

        # Iterate through each spine
        for i, spine_ip in enumerate(self.spine_ips):
            config_data = {
                'is_spine': True,
                'spine_ip': spine_ip,
                'spine_as': overlay_as,
                'leaf_ips': self.leaf_ips,
                'service_count': self.service_count,
                'base_vxlan_vlan_id': self.base_vxlan_vlan_id,
                'overlay_service_type': self.overlay_service_type,
                'enumerate': enumerate,
                'spine_tag': spine_tags[i],  # Pass spine tag
                'leaf_tags': leaf_tags,  # Pass leaf tags
                'GenerateOverlayBtn_State': self.GenerateOverlayBtn_State,
            }

            # Only generate ESI for 'vxlan_vlan_aware_t2_seamless_stitching'
            if self.overlay_service_type == 'vxlan_vlan_aware_t2_seamless_stitching' or 'vxlan_vlan_aware_t2_seamless_stitching_translation_vni':
                # Initialize vxlan_vni_list for the associated leaves for this spine
                vxlan_vni_list = [None] * len(self.leaf_ips)
                esi_map = {}  # Map for storing ESI values
                for leaf_index, leaf_tag in enumerate(leaf_tags):
                    if leaf_tag == spine_tags[i]:  # If the leaf tag matches the spine tag, generate VXLAN VNI list
                        leaf_vni_list = [self.base_vxlan_vni + j + (leaf_index * 1000) for j in
                                         range(self.service_count)]
                        vxlan_vni_list[leaf_index] = leaf_vni_list

                        # ESI Generation: Check if spine tags match
                        if spine_tags[i] == leaf_tag:
                            esi_map[leaf_index] = '00:00:22:22:22:22:22:22:22:22'
                        else:
                            # Generate unique ESI based on spine IP and VLAN ID if tags don't match
                            spine_ip_parts = spine_ip.split('.')
                            spine_ip_last_two = '%02X:%02X' % (int(spine_ip_parts[2]), int(spine_ip_parts[3]))
                            vlan_hex = '%02X' % (self.base_vxlan_vlan_id % 256)
                            esi_map[leaf_index] = '00:00:' + spine_ip_last_two + ':' + vlan_hex + ':22:22:22:22:22'

                # Add the necessary data to the config for rendering
                config_data['vxlan_vni_list'] = vxlan_vni_list
                config_data['esi_map'] = esi_map

            # Render the configuration from the template
            spine_config = template.render(config_data)

            # Clean up the configuration to remove extra spaces and blank lines
            cleaned_config = "\n".join([line.strip() for line in spine_config.splitlines() if line.strip()])
            spine_configs.append(cleaned_config.strip().split('\n'))

        return spine_configs


    '''def generate_leaf_configs(self, spine_tags=None, leaf_tags=None):
        """
        Generate configurations for leaf devices.
        """
        def generate_overlay_vxlan_config(leaf_ip, leaf_index):
            """
            Generate VXLAN configuration for a specific leaf device based on the number of service counts.
            """
            def generate_service_ip_v6(service_count, leaf_index, service_type):
                """
                Generate IPv6 addresses for each service with handling for block overflow.
                base_ipv6_parts: list of exploded IPv6 address parts (8 blocks).
                """
                ipv6_first_block = int(self.base_ipv6_parts[0], 16)  # Example: '2001'
                ipv6_second_block = int(self.base_ipv6_parts[1], 16)  # Example: '0192'
                ipv6_third_block = int(self.base_ipv6_parts[2], 16)  # Example: '0000'
                ipv6_service_ips = []
                #if service_type == 'type5_vxlan':
                if service_type in ['type5_vxlan', 'type5_vxlan_vlan_aware']:
                    ipv6_third_block += leaf_index
                    for i in range(service_count):
                        if ipv6_third_block > 0xffff:
                            ipv6_third_block = 0
                            ipv6_second_block += 1
                            if ipv6_second_block > 0xffff:
                                raise ValueError("IPv6 address range exhausted.")
                        # Generate IPv6 address
                        ipv6_service_ip = f"{ipv6_first_block:x}:{ipv6_second_block:x}:{ipv6_third_block:x}::1"
                        ipv6_service_ips.append(ipv6_service_ip)
                        ipv6_third_block += 1  # Increment third block for next service
                else:
                    for i in range(service_count):
                        ipv6_service_ip = f"{ipv6_first_block:x}:{ipv6_second_block:x}:{ipv6_third_block:x}::{leaf_index + 1}"
                        ipv6_service_ips.append(ipv6_service_ip)
                        ipv6_third_block += 1
                        if ipv6_third_block > 0xffff:
                            ipv6_third_block = 0
                            ipv6_second_block += 1
                            if ipv6_second_block > 0xffff:
                                raise ValueError("IPv6 address range exhausted.")

                return ipv6_service_ips

            def generate_service_ip(service_count, leaf_index, service_type):
                """
                Generate IPs for each service with handling for octet overflow.
                """
                first_octet = self.base_ip_parts[0]
                second_octet = self.base_ip_parts[1]
                third_octet = self.base_ip_parts[2]
                service_ips = []
                #if service_type == 'type5_vxlan':
                if service_type in ['type5_vxlan', 'type5_vxlan_vlan_aware']:
                    # Increment third_octet based on leaf_index
                    third_octet += leaf_index
                    for i in range(service_count):
                        if third_octet > 254:
                            third_octet = 0  # Reset third_octet if it exceeds 254
                            second_octet += 1  # Increment second_octet to change subnet
                            if second_octet > 254:
                                raise ValueError("IP range exhausted.")
                        # Generate service IP with updated octets
                        service_ip_address = f"{first_octet}.{second_octet}.{third_octet}.{1}"  # Use constant 1 for the last octet
                        service_ips.append(service_ip_address)
                        third_octet += 1
                else:
                    for i in range(service_count):
                        # For other service types, increment third octet per service
                        service_ip_address = f"{first_octet}.{second_octet}.{third_octet}.{leaf_index + 1}"
                        service_ips.append(service_ip_address)
                        third_octet += 1
                        if third_octet > 254:
                            third_octet = 0
                            second_octet += 1
                            if second_octet > 254:
                                second_octet = 0
                                first_octet += 1
                                if first_octet > 254:
                                    raise ValueError("IP range exhausted.")
                return service_ips

            # Generate service IPs for the current leaf
            service_ips = generate_service_ip(self.service_count, leaf_index, self.overlay_service_type)
            v6_service_ips = generate_service_ip_v6(self.service_count, leaf_index, self.overlay_service_type)
            #print(f"v6_service_ips: {v6_service_ips}")
            #print(f"service_ips: {service_ips}")
            # Generate service IPs for all other leaves
            other_service_ips_list = []
            for other_leaf_index, other_leaf_ip in enumerate(self.leaf_ips):
                if other_leaf_index != leaf_index:  # Skip the current leaf itself
                    other_service_ips_list.append(
                        generate_service_ip(self.service_count, other_leaf_index, self.overlay_service_type)
                    )

            # Flatten the list of service IPs for other leaves and match them per VLAN
            other_service_ips_per_vlan = [
                [ips[vlan_index] for ips in other_service_ips_list]
                for vlan_index in range(self.service_count)
            ]


            # VXLAN VNI Generation Logic
            vxlan_vni_list = []
            if self.overlay_service_type == 'vxlan_vlan_aware_t2_seamless_stitching' or 'vxlan_vlan_aware_t2_seamless_stitching_translation_vni':
                # Custom VNI logic for this service type
                for i in range(self.service_count):
                    vxlan_vni = self.base_vxlan_vni + i + (leaf_index * 1000)  # Unique VNIs per leaf
                    vxlan_vni_list.append(vxlan_vni)
            else:
                # Standard VNI logic for other service types
                for i in range(self.service_count):
                    vxlan_vni = self.base_vxlan_vni + i
                    vxlan_vni_list.append(vxlan_vni)

            # Template selection using a dictionary
            template_map = {
                'mac_vrf_vlan_aware': 'mac_vrf_vlan_aware_template.j2',
                'mac_vrf_vlan_based': 'mac_vrf_vlan_based_template.j2',
                'type5_vxlan': 'vxlan_type5_vlan_based_template.j2',
                'type5_vxlan_vlan_aware': 'vxlan_type5_vlan_aware_template.j2',
                'vxlan_type2_to_sym_type2_stitching': 'vxlan_type2_to_sym_type2_stitching.j2',
                'vxlan_type2_to_sym_type5': 'vxlan_type2_to_sym_type5_tmpl.j2',
                'vxlan_bgp_over_sym_type5': 'vxlan_bgp_over_sym_type5_tmpl.j2',
                'vxlan_vlan_aware_t2_seamless_stitching': 'vxlan_vlan_aware_t2_seamless_stitching.j2',
                'vxlan_vlan_aware_t2_seamless_stitching_translation_vni': 'vxlan_vlan_aware_t2_seamless_stitching_translation_vni.j2',
                'leaf_config': 'leaf_config_tmpl.j2',
            }

            template_name = template_map.get(self.overlay_service_type)
            leaf_template_name = template_map.get('leaf_config')
            if not template_name:
                return "Invalid overlay configuration type"

            # Prepare context for template rendering
            context = {
                'leaf_ip': leaf_ip,
                'leaf_index': leaf_index,
                'service_count': self.service_count,
                'vxlan_vni_list': vxlan_vni_list,  # Pass the list of VXLAN VNIs
                'base_vxlan_vni': self.base_vxlan_vni,
                'base_vxlan_vlan_id': self.base_vxlan_vlan_id,
                'service_ips': service_ips,
                'v6_service_ips': v6_service_ips,
                'service_int_leaves': self.service_int_leaves,
                'esi_lag_services': self.esi_lag_services,
                'other_service_ips_per_vlan': other_service_ips_per_vlan,
                'enumerate': enumerate,
                'overlay_as': self.leaf_base_as,  # Include AS number
                'spine_ips': self.spine_ips,  # Include spine IPs for BGP neighbors
                'GenerateOverlayBtn_State': self.GenerateOverlayBtn_State,
                'overlay_service_type': self.overlay_service_type,  # Include service type
            }
            #print(context)
            # Conditionally include 'leaf_tags' if required by the service type
            if leaf_tags is not None:
                context['leaf_tags'] = leaf_tags
            if spine_tags is not None:
                # Prepare spine IPs and tags for BGP neighbors
                spine_ips_with_tags = [
                    (spine_ip, spine_tag) for spine_ip, spine_tag in zip(self.spine_ips, spine_tags)
                ]
                context['spine_ips_with_tags'] = spine_ips_with_tags

            # Load and render the Jinja2 templates
            template = self.load_template(template_name)
            leaf_template = self.load_template(leaf_template_name)
            rendered_leaf_config = leaf_template.render(context)
            rendered_config = template.render(context)
            # Clean and combine the configurations
            cleaned_leaf_config_lines = [
                line.strip() for line in rendered_leaf_config.splitlines() if line.strip()
            ]
            cleaned_template_lines = [
                line.strip() for line in rendered_config.splitlines() if line.strip()
            ]
            combined_config = cleaned_leaf_config_lines + cleaned_template_lines

            return combined_config

        leaf_configs = []
        for j, leaf_ip in enumerate(self.leaf_ips):
            # Generate VXLAN overlay config for the leaf
            vxlan_config = generate_overlay_vxlan_config(leaf_ip, j)
            # Append final config to list
            leaf_configs.append(vxlan_config)

        return leaf_configs'''

    def generate_leaf_configs(self, spine_tags=None, leaf_tags=None):
        """
        Generate configurations for leaf devices.
        """

        def generate_overlay_vxlan_config(leaf_ip, leaf_index):
            """
            Generate VXLAN configuration for a specific leaf device.
            """

            def generate_service_ip(service_count, leaf_index):
                """
                Generate IPv4 addresses for each service.
                """
                first_octet, second_octet, third_octet = self.base_ip_parts[:3]
                service_ips = []

                for i in range(service_count):
                    service_ips.append(f"{first_octet}.{second_octet}.{third_octet}.{leaf_index + 1}")
                    third_octet += 1
                    if third_octet > 254:
                        third_octet = 0
                        second_octet += 1
                        if second_octet > 254:
                            second_octet = 0
                            first_octet += 1
                            if first_octet > 254:
                                raise ValueError("IPv4 address range exhausted.")

                return service_ips

            def generate_service_ip_v6(service_count, leaf_index):
                """
                Generate IPv6 addresses for each service.
                """
                ipv6_first, ipv6_second, ipv6_third = (int(self.base_ipv6_parts[i], 16) for i in range(3))
                ipv6_service_ips = []

                for i in range(service_count):
                    ipv6_service_ips.append(f"{ipv6_first:x}:{ipv6_second:x}:{ipv6_third:x}::{leaf_index + 1}")
                    ipv6_third += 1
                    if ipv6_third > 0xFFFF:
                        ipv6_third = 0
                        ipv6_second += 1
                        if ipv6_second > 0xFFFF:
                            raise ValueError("IPv6 address range exhausted.")

                return ipv6_service_ips

            # ✅ Generate service IPs
            service_ips = generate_service_ip(self.service_count, leaf_index)
            v6_service_ips = generate_service_ip_v6(self.service_count, leaf_index)

            if not service_ips:
                raise ValueError(f"Service IPs not generated for leaf {leaf_ip} (index {leaf_index})")

            # ✅ VXLAN VNI Generation
            vxlan_vni_list = [
                self.base_vxlan_vni + i + (leaf_index * 1000)
                for i in range(self.service_count)
            ]

            # ✅ Template selection: Prefer user template if available
            template_map = {
                'mac_vrf_vlan_aware': 'mac_vrf_vlan_aware_template.j2',
                'mac_vrf_vlan_based': 'mac_vrf_vlan_based_template.j2',
                'type5_vxlan': 'vxlan_type5_vlan_based_template.j2',
                'type5_vxlan_vlan_aware': 'vxlan_type5_vxlan_vlan_aware_template.j2',
                'vxlan_type2_to_sym_type2_stitching': 'vxlan_type2_to_sym_type2_stitching.j2',
                'vxlan_type2_to_sym_type5': 'vxlan_type2_to_sym_type5_tmpl.j2',
                'vxlan_bgp_over_sym_type5': 'vxlan_bgp_over_sym_type5_tmpl.j2',
                'vxlan_vlan_aware_t2_seamless_stitching': 'vxlan_vlan_aware_t2_seamless_stitching.j2',
                'vxlan_vlan_aware_t2_seamless_stitching_translation_vni': 'vxlan_vlan_aware_t2_seamless_stitching_translation_vni.j2',
            }

            template_name = self.user_template if self.user_template else template_map.get(self.overlay_service_type)
            leaf_template_name = 'leaf_config_tmpl.j2'  # ✅ Always use default leaf template

            if not template_name:
                raise ValueError(f"Invalid overlay configuration type: {self.overlay_service_type}")

            # ✅ Load Templates
            if self.user_template:
                env = Environment(loader=FileSystemLoader(os.path.dirname(self.user_template)))
                template = env.get_template(os.path.basename(self.user_template))
            else:
                template = self.load_template(template_name)

            leaf_template = self.load_template(leaf_template_name)

            # ✅ Prepare context for template rendering
            context = {
                'leaf_ip': leaf_ip,
                'leaf_index': leaf_index,
                'service_count': self.service_count,
                'vxlan_vni_list': vxlan_vni_list,
                'base_vxlan_vni': self.base_vxlan_vni,
                'base_vxlan_vlan_id': self.base_vxlan_vlan_id,
                'service_ips': service_ips,
                'v6_service_ips': v6_service_ips,
                'service_int_leaves': self.service_int_leaves,
                'esi_lag_services': self.esi_lag_services,
                'overlay_as': self.leaf_base_as,
                'spine_ips': self.spine_ips,
                'GenerateOverlayBtn_State': self.GenerateOverlayBtn_State,
                'overlay_service_type': self.overlay_service_type,
            }

            if leaf_tags is not None:
                context['leaf_tags'] = leaf_tags
            if spine_tags is not None:
                context['spine_ips_with_tags'] = [
                    (spine_ip, spine_tag) for spine_ip, spine_tag in zip(self.spine_ips, spine_tags)
                ]

            # ✅ Render Templates
            rendered_leaf_config = leaf_template.render(context)
            rendered_config = template.render(context)

            # ✅ Ensure proper formatting
            cleaned_leaf_config = "\n".join(line.strip() for line in rendered_leaf_config.splitlines() if line.strip())
            cleaned_config = "\n".join(line.strip() for line in rendered_config.splitlines() if line.strip())

            # ✅ Return structured output
            return cleaned_leaf_config.split('\n') + cleaned_config.split('\n')

        # ✅ Generate leaf configs
        leaf_configs = [generate_overlay_vxlan_config(leaf_ip, j) for j, leaf_ip in enumerate(self.leaf_ips)]
        return leaf_configs

    def generate_configs(self,spine_tags=None, leaf_tags=None):
        """
        Generate both spine and leaf configurations.
        """
        #spine_configs = self.generate_spine_configs()
        spine_configs = self.generate_spine_configs(spine_tags, leaf_tags)
        leaf_configs = self.generate_leaf_configs(spine_tags, leaf_tags)
        return spine_configs, leaf_configs


def generate_vlan_config(interface_prefixes, vlan_ids, base_ip_parts, access, trunk, native_vlanid,
                         native_vlanid_value,
                         ip_versions, last_octet):
    config_lines = []
    vlan_irb_lines = []
    interface_lines = []
    native_vlanid_configured = {interface_prefix: False for interface_prefix in interface_prefixes}
    for vlan_id in vlan_ids:
        if 'ipv4' in ip_versions and 'ipv4' in base_ip_parts:
            ip_address = f"{base_ip_parts['ipv4']}.{last_octet}/24"
            vlan_irb_lines.append(f"set vlans v{vlan_id} vlan-id {vlan_id}")
            vlan_irb_lines.append(f"set interfaces irb.{vlan_id} family inet address {ip_address}")
            # Increment IPv4 address
            ip_parts = list(map(int, base_ip_parts['ipv4'].split('.')))
            if ip_parts[2] == 254:
                ip_parts[1] += 1
                ip_parts[2] = 0
            else:
                ip_parts[2] += 1
            base_ip_parts['ipv4'] = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"

        if 'ipv6' in ip_versions and 'ipv6' in base_ip_parts:
            ip_address = f"{base_ip_parts['ipv6']}{last_octet}/64"
            vlan_irb_lines.append(f"set vlans v{vlan_id} vlan-id {vlan_id}")
            vlan_irb_lines.append(f"set interfaces irb.{vlan_id} family inet6 address {ip_address}")
            # Increment IPv6 address
            ip_parts = base_ip_parts['ipv6'].rstrip(':').split(':')
            last_segment = int(ip_parts[-1], 16) if ip_parts[-1] else 0
            last_segment += 1
            ip_parts[-1] = hex(last_segment)[2:]
            base_ip_parts['ipv6'] = ':'.join(ip_parts) + ':'

        vlan_irb_lines.append(f"set vlans v{vlan_id} l3-interface irb.{vlan_id}")

    for interface_prefix in interface_prefixes:
        interface_name = f"{interface_prefix}.0"
        for vlan_id in vlan_ids:
            if access:
                interface_lines.append(
                    f"set interfaces {interface_name} family ethernet-switching interface-mode access vlan members v{vlan_id}")
            elif trunk:
                if native_vlanid and not native_vlanid_configured[interface_prefix]:
                    interface_lines.append(f"set interfaces {interface_name} native-vlan-id {native_vlanid_value}")
                    native_vlanid_configured[interface_prefix] = True
                interface_lines.append(
                    f"set interfaces {interface_name} family ethernet-switching interface-mode trunk vlan members v{vlan_id}")
    config_lines.extend(vlan_irb_lines)
    config_lines.extend(interface_lines)
    return config_lines

