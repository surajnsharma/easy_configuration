#utils.py#
from flask import flash, redirect, url_for
from flask_login import current_user
from app import socketio
from functools import wraps
import os, re, paramiko, subprocess, time
import logging,ipaddress
from logging.handlers import RotatingFileHandler
from jnpr.junos.exception import ConnectError, ConnectAuthError, ConfigLoadError, CommitError, LockError, UnlockError,ConnectUnknownHostError,RpcError
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
import socket
from datetime import datetime, timedelta
from .models import GpuSystem, db
import yaml,json
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import psutil
from jinja2 import Environment, FileSystemLoader, TemplateNotFound
import hashlib
from lxml import etree
from jnpr.junos.utils.scp import SCP
from jnpr.junos.utils.sw import SW
from ncclient.transport.errors import SSHError


# Define the function to load and render Jinja templates from /templates/ConfigTemplates
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


'''class DeviceConnectorClass:
    def __init__(self, hostname, ip, username, password):
        self.hostname = hostname
        self.ip = ip
        self.username = username
        self.password = password

    def is_valid_hostname_or_ip(self):
        """
        Checks if the provided hostname or IP address can be resolved.
        :return: True if valid, False otherwise.
        """
        try:
            socket.gethostbyname(self.ip)
            return True
        except socket.error:
            return False

    def connect_to_device(self):
        """
        Establishes a connection to the device using the provided credentials.
        Handles connection authentication and general connection errors.
        """
        logging.info(f"Attempting to connect to device: {self.hostname} at IP: {self.ip}")

        # Validate hostname or IP address
        if not self.is_valid_hostname_or_ip():
            logging.error(f"Invalid hostname or IP address: {self.ip}")
            raise Exception(f"Invalid hostname or IP address: {self.ip}")
        try:
            dev=Device(host=self.ip, user=self.username, passwd=self.password, port=22)
            dev.open()
            if dev.connected:
                logging.info(f"Successfully connected to {self.hostname} at IP: {self.ip}")
                return dev  # Return the device object
            else:
                logging.error(f"Failed to establish connection to {self.hostname} (dev.connected is False)")
                raise Exception(f"Failed to establish connection to {self.hostname} at IP: {self.ip}")
        except ConnectAuthError as e:
            logging.error(f"Connection authentication error for device {self.hostname}: {str(e)}")
            raise ConnectAuthError(f"Connection authentication error for device {self.hostname}: {str(e)}")
        except ConnectUnknownHostError as e:
            logging.error(f"Unknown host error for device {self.hostname}: {str(e)}")
            raise ConnectUnknownHostError(f"Unknown host: Could not resolve {self.hostname}. Please check the hostname or DNS configuration.")
        except ConnectError as e:
            logging.error(f"Connection error for device {self.hostname}: {str(e)}")
            raise ConnectError(f"Connection error for device {self.hostname}: {str(e)}")
        except Exception as e:
            logging.error(f"Error connecting to device {self.hostname}: {str(e)}")
            raise Exception(f"Error connecting to device {self.hostname}: {str(e)}")'''


class DeviceConnectorClass:
    def __init__(self, hostname, ip, username, password):
        self.hostname = hostname
        self.ip = ip
        self.username = username
        self.password = password

    def is_valid_hostname_or_ip(self):
        """
        Checks if the provided hostname or IP address can be resolved.
        :return: True if valid, False otherwise.
        """
        try:
            socket.gethostbyname(self.ip)
            return True
        except socket.error:
            return False

    def connect_to_device(self):
        """
        Establishes a connection to the device using the provided credentials.
        Handles connection authentication and general connection errors.
        """
        logging.info(f"Attempting to connect to device: {self.hostname} at IP: {self.ip}")

        # Validate hostname or IP address
        if not self.is_valid_hostname_or_ip():
            logging.error(f"Invalid hostname or IP address: {self.ip}")
            raise Exception(f"Invalid hostname or IP address: {self.ip}")

        try:
            dev = Device(host=self.ip, user=self.username, passwd=self.password, port=22)
            dev.open()

            if dev.connected:
                logging.info(f"Successfully connected to {self.hostname} at IP: {self.ip}")
                return dev  # Return the device object
            else:
                logging.error(f"Failed to establish connection to {self.hostname} (dev.connected is False)")
                raise Exception(f"Failed to establish connection to {self.hostname} at IP: {self.ip}")

        except ConnectAuthError as e:
            logging.error(f"Connection authentication error for device {self.hostname}: {str(e)}")
            raise ConnectAuthError(f"Connection authentication error for device {self.hostname}: {str(e)}")

        except ConnectUnknownHostError as e:
            logging.error(f"Unknown host error for device {self.hostname}: {str(e)}")
            raise ConnectUnknownHostError(
                f"Unknown host: Could not resolve {self.hostname}. Please check the hostname or DNS configuration.")

        except SSHError as e:
            logging.error(f"SSH error for device {self.hostname}: {str(e)}")
            raise SSHError(f"SSH error while connecting to {self.hostname}: {str(e)}")

        except paramiko.ssh_exception.SSHException as e:
            logging.error(f"Paramiko SSH exception for device {self.hostname}: {str(e)}")
            raise paramiko.ssh_exception.SSHException(f"SSH exception for device {self.hostname}: {str(e)}")

        except socket.error as e:
            logging.error(f"Socket error for device {self.hostname}: {str(e)}")
            raise socket.error(f"Socket error for device {self.hostname}: {str(e)}")
        except ConnectionResetError as e:
            logging.error(f"Connection reset by peer for device {self.hostname}: {str(e)}")
            raise ConnectionResetError(f"Connection reset by peer for device {self.hostname}: {str(e)}")

        except ConnectError as e:
            logging.error(f"General connection error for device {self.hostname}: {str(e)}")
            raise ConnectError(f"Connection error for device {self.hostname}: {str(e)}")

        except Exception as e:
            logging.error(f"General error connecting to device {self.hostname}: {str(e)}")
            raise Exception(f"General error connecting to device {self.hostname}: {str(e)}")


class BuildLLDPConnectionClass:
    def __init__(self, hostname,device_in_database):
        """
        Initialize with the hostname of the device.
        """
        self.hostname = hostname
        self.device_list=device_in_database

    '''def get_lldp_neighbors(self, dev):
        """
        Fetches the LLDP neighbors for the given device.
        """
        neighbors_dict = {}
        try:
            neighbors = dev.rpc.get_lldp_neighbors_information()
            logging.info(f"LLDP neighbors information for {self.hostname}: {neighbors}")
            for neighbor in neighbors.findall('.//lldp-neighbor-information'):
                interface = neighbor.find('lldp-local-port-id').text.strip()
                remote_system_name = neighbor.find('lldp-remote-system-name').text.strip()
                remote_port_desc = neighbor.find('lldp-remote-port-description').text.strip()
                sanitized_port_desc = self.sanitize_port_desc(remote_system_name, interface, remote_port_desc)
                if sanitized_port_desc:  # Only process if description is valid
                    if self.hostname not in neighbors_dict:
                        neighbors_dict[self.hostname] = []
                    neighbors_dict[self.hostname].append((remote_system_name, interface, sanitized_port_desc))
                else:
                    logging.warning(f"Invalid port description: {remote_port_desc}")
        except Exception as e:
            logging.error(f"Failed to fetch LLDP neighbors for {self.hostname}: {e}")
            raise Exception(f"Failed to fetch LLDP neighbors for {self.hostname}: {e}")

        return neighbors_dict'''

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
                    print(
                        f"Added neighbor - System: {remote_system_name}, Interface: {interface}, Port Desc: {sanitized_port_desc}")
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



class InfluxDBConnectionV2:
    def __init__(self):
        self.url = "http://localhost:8086"
        self.token = "g84qg1Dz4GxjuAqioniTJsl1K_ln3JVPiU4FshYJ3fUjS5n38cgAMtCcLIBt_TVtmf8IWLfV_wxym-f4v85qjw=="
        self.org = "juniper"
        self.bucket = "telemetry" #for server telemetry
        self.intbucket="metrics" #for interface telemetry
        self.client = InfluxDBClient(url=self.url, token=self.token, org=self.org)

    def get_measurements_for_device(self, device_name):
        query = f'SHOW MEASUREMENTS WITH MEASUREMENT =~ /^{device_name}.*/'

        curl_command = [
            'curl', '--get', f'{self.url}/query',
            '--header', f'Authorization: Token {self.token}',
            '--data-urlencode', f'db={self.intbucket}',
            '--data-urlencode', f'q={query}'
        ]

        try:
            result = subprocess.run(curl_command, capture_output=True, text=True, check=True)
            output = result.stdout
            data = json.loads(output)

            if 'results' in data and data['results'][0].get('series'):
                measurements = [measurement[0] for measurement in data['results'][0]['series'][0]['values']]
                return measurements
            else:
                return []

        except subprocess.CalledProcessError as e:
            print(f"Error executing curl command: {e}")
            return []
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON response: {e}")
            return []

    def query_interface_counters(self, limit=10, source_filter=None, measurement_filter="interface_counters",
                                 interfaces_filter=None):
        influxql_query = f'SELECT * FROM "{measurement_filter}" WHERE "source" = \'{source_filter}\''

        if interfaces_filter:
            interfaces_condition = ' OR '.join(
                [f'"interface_name" = \'{interface}\'' for interface in interfaces_filter])
            influxql_query += f' AND ({interfaces_condition})'

        influxql_query += f' ORDER BY time DESC LIMIT {limit}'

        # Execute the curl command using subprocess
        curl_command = [
            'curl', '--get', 'http://localhost:8086/query',
            '--header', f'Authorization: Token {self.token}',
            '--data-urlencode', f'db={self.intbucket}',
            '--data-urlencode', f'q={influxql_query}'
        ]

        try:
            result = subprocess.run(curl_command, capture_output=True, text=True, check=True)
            output = result.stdout
            data = json.loads(output)
            return data

        except subprocess.CalledProcessError as e:
            print(f"Error executing curl command: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON response: {e}")
            return None

    def query_interface_names(self, source_filter=None, measurement_filter=None):
        if measurement_filter is None:
            raise ValueError("A measurement must be selected.")

        # Construct the InfluxQL query string
        influxql_query = f'SHOW TAG VALUES FROM "{measurement_filter}" WITH KEY = "interface_name" WHERE "source" = \'{source_filter}\''

        # Execute the curl command using subprocess
        curl_command = [
            'curl', '--get', 'http://localhost:8086/query',
            '--header', f'Authorization: Token {self.token}',
            '--data-urlencode', f'db={self.intbucket}',
            '--data-urlencode', f'q={influxql_query}'
        ]

        try:
            result = subprocess.run(curl_command, capture_output=True, text=True, check=True)
            output = result.stdout

            # Parse the output as JSON
            data = json.loads(output)
            return data

        except subprocess.CalledProcessError as e:
            print(f"Error executing curl command: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON response: {e}")
            return None

    def delete_measurement(self, measurement):
        query = f'DROP MEASUREMENT "{measurement}"'
        curl_command = [
            'curl', '--get', 'http://localhost:8086/query',
            '--header', f'Authorization: Token {self.token}',
            '--data-urlencode', f'db={self.intbucket}',
            '--data-urlencode', f'q={query}'
        ]

        try:
            result = subprocess.run(curl_command, capture_output=True, text=True, check=True)
            if result.returncode == 0:
                print(f"Measurement '{measurement}' deleted successfully.")
                return True
            else:
                print(f"Failed to delete measurement '{measurement}'.")
                return False
        except subprocess.CalledProcessError as e:
            print(f"Error executing curl command: {e}")
            return False

    def get_device_hosts(self):
        query = '''
        from(bucket: "telemetry")
          |> range(start: -24h)
          |> distinct(column: "host")
        '''
        result = self.client.query_api().query(query=query, org=self.org)
        if result:
            hosts = list(set([record.get_value() for table in result for record in table.records]))
        else:
            hosts = []
        return hosts


    def query_metrics(self, device_hosts, record_limit, selected_date=None):
        formatted_hosts = "[" + ",".join([f'"{host}"' for host in device_hosts]) + "]"

        try:
            # Validate and format the date if provided
            if selected_date:
                try:
                    start_date = f'{selected_date}T00:00:00Z'
                    end_date = f'{selected_date}T23:59:59Z'
                    date_filter = f'  |> range(start: {start_date}, stop: {end_date})'
                except ValueError as e:
                    raise ValueError(f"Invalid date format: {selected_date}. Expected format is YYYY-MM-DD.") from e
            else:
                date_filter = f'  |> range(start: -24h)'

            # Construct the query
            query = (
                f'from(bucket: "{self.bucket}")'
                f'{date_filter}'
                f'  |> filter(fn: (r) => r._measurement == "server_metrics" and contains(value: r.host, set: {formatted_hosts}))'
                f'  |> sort(columns: ["_time"], desc: true)'
                f'  |> limit(n: {record_limit})'
            )

            # Execute the query
            result = self.client.query_api().query(query=query, org=self.org)
            return result if result else []

        except Exception as e:
            logging.error(f"Failed to execute query_metrics: {e}")
            return None


    def delete_metric(self, host, time, field):
        try:
            logging.info(f"Original time: {time}")
            parsed_time = datetime.strptime(time, '%a, %d %b %Y %H:%M:%S %Z')
            start_time = parsed_time.isoformat() + 'Z'
            end_time = (parsed_time + timedelta(seconds=1)).isoformat() + 'Z'
            logging.info(f"Start time: {start_time}, End time: {end_time}")

            predicate = f'_measurement="server_metrics" AND host="{host}"'
            logging.info(f"Delete predicate: {predicate}")

            delete_api = self.client.delete_api()
            delete_api.delete(
                start=start_time,
                stop=end_time,
                predicate=predicate,
                bucket=self.bucket,
                org=self.org
            )
            logging.info("Metric deleted successfully.")
            return True
        except Exception as e:
            logging.error(f"Error deleting metric: {str(e)}")
            return False

    def get_gpu_system_by_id(self,system_id):
        # Query the GpuSystem model to get the system by its ID
        system = GpuSystem.query.get(system_id)
        if system:
            return {
                'node_ip': system.node_ip,
                'user': system.user,
                'password': system.password
            }
        return None


    def server_telemetry(self, REMOTE_HOST, USERNAME, PASSWORD):
        SSH_TIMEOUT = 10
        logging.info(f"Starting connection to {REMOTE_HOST}...")

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(REMOTE_HOST, username=USERNAME, password=PASSWORD, timeout=SSH_TIMEOUT)
            logging.info(f"Successfully connected to {REMOTE_HOST}.")

            python_script = """
import psutil
cpu_usage = psutil.cpu_percent(interval=1)
memory_usage = psutil.virtual_memory().percent
disk_usage = psutil.disk_usage('/').percent
print(cpu_usage)
print(memory_usage)
print(disk_usage)
"""
            stdin, stdout, stderr = ssh.exec_command(f"python3 -c \"{python_script}\"")
            output = stdout.read().decode().splitlines()
            error_output = stderr.read().decode()

            if error_output:
                raise Exception(f"Error output from remote host {REMOTE_HOST}: {error_output.strip()}")

            if len(output) != 3:
                raise Exception(f"Unexpected output from remote host {REMOTE_HOST}: {output}")

            cpu_usage = float(output[0])
            memory_usage = float(output[1])
            disk_usage = float(output[2])

        except Exception as e:
            logging.error(f"Exception occurred on host {REMOTE_HOST}: {e}")
            raise Exception(f"{e} on host {REMOTE_HOST}")

        finally:
            ssh.close()

        try:
            write_api = self.client.write_api(write_options=SYNCHRONOUS)
            point = Point("server_metrics") \
                .tag("host", REMOTE_HOST) \
                .field("cpu_usage", cpu_usage) \
                .field("memory_usage", memory_usage) \
                .field("disk_usage", disk_usage)

            write_api.write(bucket=self.bucket, org=self.org, record=point)
            logging.info(f"Data written to InfluxDB for host {REMOTE_HOST}")
        except Exception as e:
            logging.error(f"Failed to collect metrics or write to InfluxDB for host {REMOTE_HOST}: {e}")
            raise Exception(f"Failed to collect metrics or write to InfluxDB on host {REMOTE_HOST}: {e}")
        finally:
            self.client.close()



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


    '''def check_storage_space(self, dev, required_space):
        try:
            storage_info = dev.rpc.get_system_storage()
            max_available_space = 0
            selected_mount_point = None
            for filesystem in storage_info.xpath('//filesystem'):
                mounted_on = filesystem.findtext('mounted-on')
                avail_blocks = filesystem.findtext('available-blocks')
                if avail_blocks and ('/tmp' in mounted_on or 'var' in mounted_on):
                    avail_bytes = int(avail_blocks) * 1024  # Convert blocks to bytes
                    logging.info(f"Device {dev.hostname} - {mounted_on}: available space {avail_bytes} bytes")
                    if avail_bytes > max_available_space:
                        max_available_space = avail_bytes
                        selected_mount_point = mounted_on
                        logging.info(f"Selected mount point for Image: {dev.hostname}: {selected_mount_point}")

            if max_available_space >= required_space:
                return True, max_available_space, selected_mount_point
            else:
                return False, max_available_space, selected_mount_point
        except Exception as e:
            logging.error(f"Error checking storage space: {str(e)}")
            return False, None, None'''

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



class GNMIConfigBuilder:
    def __init__(self, influx_token, gnmi_server):
        self.config = {
            'targets': {},
            'outputs': {
                'default': {
                    'type': 'influxdb',
                    'address': f'http://{gnmi_server}:8086',
                    'bucket': 'metrics',
                    'token': influx_token,
                    'org': 'juniper',
                    'precision': 'ns'
                }
            },
            'subscriptions': {}
        }

    def add_device(self, target, port, address, username, password, paths, subscription_mode, sample_interval):
        # Add the target to the configuration
        self.config['targets'][target] = {
            'address': f'{address}:{port}',
            'username': username,
            'password': password,
            'tls': {
                'enabled': False
            },
            'insecure': True
        }

        # Create subscriptions for each path for this target
        for path in paths:
            # Construct a unique subscription name for each path
            subscription_name = f'{target}_{path.strip("/").replace("/", "_")}'
            self.config['subscriptions'][subscription_name] = {
                'paths': [path],
                'mode': subscription_mode.lower(),
                'encoding': 'proto',
                'sample_interval': f'{sample_interval}s'
            }

    def build_config(self):
        return yaml.dump(self.config, default_flow_style=False)

    def save_to_file(self, file_path):
        # Ensure the directory exists
        directory = os.path.dirname(file_path)
        if not os.path.exists(directory):
            os.makedirs(directory)

        # Save the configuration YAML to a file
        with open(file_path, 'w') as file:
            yaml.dump(self.config, file, default_flow_style=False)


"""class GNMIConfigBuilder:
    def __init__(self, influx_token, target,port, address, username, password, gnmi_server, paths, subscription_mode, sample_interval):
        self.config = {
            'targets': {
                target: {
                    'address': f'{address}:{port}',
                    'username': username,
                    'password': password,
                    'tls': {
                        'enabled': False
                    },
                    'insecure': True
                }
            },
            'outputs': {
                'default': {
                    'type': 'influxdb',
                    'address': f'http://{gnmi_server}:8086',
                    'bucket': 'metrics',
                    'token': influx_token,
                    'org': 'juniper',
                    'precision': 'ns'
                }
            },
            'subscriptions': {
                'interface_counters': {
                    'paths': paths,
                    'mode': subscription_mode.lower(),
                    'encoding': 'proto',
                    'sample_interval': f'{sample_interval}s'
                }
            }
        }

    def build_config(self):
        return yaml.dump(self.config, default_flow_style=False)

    def save_to_file(self, file_path):
        # Ensure the directory exists
        directory = os.path.dirname(file_path)
        if not os.path.exists(directory):
            os.makedirs(directory)

        # Save the configuration YAML to a file
        with open(file_path, 'w') as file:
            yaml.dump(self.config, file, default_flow_style=False)"""


class TelemetryUtils:
    def __init__(self, app):
        self.app = app

    def stop_stream(self):
        pid = current_user.telemetry_pid  # Retrieve PID from the logged-in user's database record
        try:
            if pid:
                process = psutil.Process(pid)
                for child in process.children(recursive=True):  # Kill all child processes
                    child.kill()
                process.kill()  # Kill the main process

                # Clear the PID in the database
                current_user.telemetry_pid = None
                db.session.commit()

                return {"status": "success", "message": "Telemetry stream stopped successfully"}
            else:
                return {"status": "error", "message": "No telemetry stream is currently running"}
        except Exception as e:
            return {"status": "error", "message": str(e)}


    def start_telemetry_stream(self,devices,telemetry_port):
        pid = current_user.telemetry_pid  # Retrieve PID from the logged-in user's database record
        try:
            if pid:
                return {"status": "error", "message": "Telemetry stream is already running"}

            config_path = os.path.join(self.app.config['TELEMETRY_FOLDER'], 'gnmi-config.yaml')
            logging.info(f"config_path: utils.py-start_telemetry_stream: {config_path}")
            log_path = os.path.join(self.app.config['TELEMETRY_FOLDER'], 'telemetry_debug.log')
            logging.info(f"log_path: utils.py-start_telemetry_stream: {log_path}")

            # Load the existing gnmi-config.yaml file
            with open(config_path, 'r') as file:
                gnmi_config = yaml.safe_load(file)

            # Build the targets section in gnmi-config.yaml
            targets = {}
            for device in devices:
                target_name = device['hostname']
                targets[target_name] = {
                    'address': f"{device['ip']}:{telemetry_port}",
                    'insecure': True,
                    'username': device['username'],
                    'password': device['password'],
                    'tls': {'enabled': False}
                }

            # Update the config with new targets
            gnmi_config['targets'] = targets

            # Save the updated gnmi-config.yaml file
            with open(config_path, 'w') as file:
                yaml.safe_dump(gnmi_config, file)
                logging.info(f"gnmi_config: utils.py-start_telemetry_stream: {gnmi_config}")

            # Start the telemetry stream
            with open(log_path, 'w') as log_file:
                process = subprocess.Popen(
                    ['gnmic', '--config', config_path, 'subscribe', '--debug', '--insecure'],
                    stdout=log_file,
                    stderr=subprocess.STDOUT
                )

            # Store the PID in the database
            current_user.telemetry_pid = process.pid
            db.session.commit()

            return {"status": "success", "message": "Telemetry stream started successfully!"}
        except Exception as e:
            return {"status": "error", "message": str(e)}


def is_reachable(ip):
    try:
        socket.gethostbyname(ip)
        return True
    except socket.error:
        return False

def get_router_details_from_db():
    router_details = []
    from app.models import DeviceInfo  # Import here to avoid circular imports
    devices = DeviceInfo.query.all()
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
        logging.info(f"Attempting to connect to {router_ip} with user {router_user}")
        emit_progress(router_ip, 0, 'Connecting')
        dev = Device(host=router_ip, user=router_user, passwd=router_password, port=22)
        dev.open()
        logging.info(f"Connection established to {router_ip}")
        emit_progress(router_ip, 25, 'Connected')
        cu = Config(dev)

        '''try:
            cu.unlock()
        except UnlockError as unlock_error:
            logging.warning(f"UnlockError: {str(unlock_error)}. Proceeding to lock the configuration.")'''

        cu.lock()
        logging.info("Loading configuration...")
        emit_progress(router_ip, 50, 'Loading configuration')

        if isinstance(config_lines, str):
            config_lines = config_lines.split('\n')
        elif not isinstance(config_lines, list):
            raise ValueError("config_lines should be a list of strings")
        clean_config_lines = [line for line in config_lines if not line.startswith("##")]
        config_to_load = "\n".join(clean_config_lines)
        #logging.info(f"Configuration to load: {config_to_load}")
        cu.load(config_to_load, format=config_format, ignore_warning=True)
        emit_progress(router_ip, 75, 'Loaded configuration')
        cu.commit()
        cu.unlock()
        logging.info("Configuration loaded successfully.")
        emit_progress(router_ip, 100, 'Completed')
        return f"** Configuration loaded successfully on {device_name} **"
    except (LockError, UnlockError) as lock_error:
        logging.error(f"LockError on {router_ip}: {str(lock_error)}")
        emit_progress(router_ip, 0, 'Error', str(lock_error))
        dev.close()
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
            dev.close()
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


def generate_config(commands, connections, local_as_mapping, delete_underlay_group, use_ipv4, use_ipv6, ip_assignments=None):
    ip_assignments = ip_assignments or {}
    subnet_counter = 1
    configured_groups = set()  # Track which BGP groups have been configured
    skip_interfaces = {'re0:mgmt-0', 'em0', 'fxp0'}  # Skip Unknown interfaces
    skip_device_patterns = ['mgmt', 'management', 'hypercloud']
    configured_interfaces = {}

    def get_ip(subnet_counter, host_id, ipv6=False):
        if ipv6:
            return f"fd00:{subnet_counter}::{host_id}"
        else:
            return f"192.168.{subnet_counter}.{host_id}"

    def get_subnet(ip_address, ipv6=False):
        if ipv6:
            return ipaddress.ip_network(ip_address + '/64', strict=False)
        else:
            return ipaddress.ip_network(ip_address + '/30', strict=False)

    def generate_bgp_group_config(group_name, use_ipv4=True, use_ipv6=False):
        commands = []
        if use_ipv4 and group_name == "underlay_v4":
            commands.append(f"set protocols bgp group {group_name} family inet unicast")
        if use_ipv6 and group_name == "underlay_v6":
            commands.append(f"set protocols bgp group {group_name} family inet6 unicast")
        return commands

    def generate_interface_group_config(interface, ipv4_address=None, ipv6_address=None):
        config_commands = [f"delete interfaces {interface}"]
        logging.info(f"Configuring interface {interface} with addresses: IPv4: {ipv4_address}, IPv6: {ipv6_address}")

        if ipv4_address:
            config_commands.append(f"set interfaces {interface} unit 0 family inet address {ipv4_address}/30")
        if ipv6_address:
            config_commands.append(f"set interfaces {interface} unit 0 family inet6 address {ipv6_address}/64")

        return config_commands

    def generate_bgp_neighbor_config(local_ip, neighbor_ip, local_as, remote_as, group_name):
        return [
            "## BGP Neighbor Config ##",
            f"set protocols bgp group {group_name} neighbor {neighbor_ip} peer-as {remote_as}",
            f"set protocols bgp group {group_name} neighbor {neighbor_ip} local-address {local_ip}",
            f"set protocols bgp group {group_name} local-as {local_as}"
        ]

    def remove_duplicates(commands_list):
        seen = set()
        result = []
        for command in commands_list:
            if command not in seen:
                seen.add(command)
                result.append(command)
        return result

    logging.info(f"connections: {connections}")
    print(connections)
    # Process connections
    for connection in connections:
        subnet = subnet_counter
        subnet_counter += 1
        host_id = 1  # Reset host_id for each new connection
        neighbor_ip_mapping = {}

        # First loop: Assign IP addresses to devices and populate neighbor_ip_mapping
        if isinstance(connection, dict):
            for device, interface in connection.items():
                if any(pattern in device.lower() for pattern in skip_device_patterns) or interface in skip_interfaces:
                    continue
                if device not in ip_assignments:
                    ip_assignments[device] = {}
                if device not in configured_interfaces:
                    configured_interfaces[device] = set()
                if interface not in ip_assignments[device]:
                    ip_assignments[device][interface] = {}
                if interface not in configured_interfaces[device]:
                    ipv4_address, ipv6_address = None, None
                    if use_ipv4:
                        ipv4_address = get_ip(subnet, host_id, ipv6=False)
                        ip_assignments[device][interface] = {"ipv4": ipv4_address}
                        neighbor_ip_mapping[f"{device}-{interface}-ipv4"] = ipv4_address
                    if use_ipv6:
                        ipv6_address = get_ip(subnet, host_id, ipv6=True)
                        ip_assignments[device][interface]["ipv6"] = ipv6_address
                        neighbor_ip_mapping[f"{device}-{interface}-ipv6"] = ipv6_address

                    configured_interfaces[device].add(interface)
                    host_id += 1

        logging.info(f"Neighbor IP Mapping: {neighbor_ip_mapping}")

        # Second loop: Use the populated neighbor_ip_mapping to create BGP configurations
        for device, interface in connection.items():
            for ip_version in ["ipv4", "ipv6"]:
                if ip_version == "ipv4" and not use_ipv4:
                    continue
                if ip_version == "ipv6" and not use_ipv6:
                    continue

                if f"{device}-{interface}-{ip_version}" not in neighbor_ip_mapping:
                    continue

                local_subnet = get_subnet(neighbor_ip_mapping[f"{device}-{interface}-{ip_version}"], ipv6=(ip_version == "ipv6"))

                for remote_device, remote_interface in connection.items():
                    if remote_device != device and f"{remote_device}-{remote_interface}-{ip_version}" in neighbor_ip_mapping:
                        remote_subnet = get_subnet(neighbor_ip_mapping[f"{remote_device}-{remote_interface}-{ip_version}"], ipv6=(ip_version == "ipv6"))
                        if local_subnet == remote_subnet:
                            local_as = local_as_mapping.get(device)
                            remote_as = local_as_mapping.get(remote_device)

                            if local_as is not None and remote_as is not None:
                                neighbor_ip = neighbor_ip_mapping[f"{remote_device}-{remote_interface}-{ip_version}"]
                                local_ip = neighbor_ip_mapping[f"{device}-{interface}-{ip_version}"]

                                group_name = "underlay_v4" if ip_version == "ipv4" else "underlay_v6"

                                if group_name not in configured_groups:
                                    group_commands = generate_bgp_group_config(group_name, use_ipv4=(ip_version == "ipv4"), use_ipv6=(ip_version == "ipv6"))
                                    commands[device].extend(group_commands)
                                    configured_groups.add(group_name)

                                bgp_commands = generate_bgp_neighbor_config(local_ip, neighbor_ip, local_as, remote_as, group_name)
                                commands[device].extend(bgp_commands)

    # Add common and interface configurations
    for device, interfaces in ip_assignments.items():
        if any(pattern in device.lower() for pattern in skip_device_patterns):
            continue
        if device not in commands:
            commands[device] = []
        if delete_underlay_group:
            if use_ipv4:
                commands[device].insert(0, f"delete protocols bgp group underlay_v4")
            if use_ipv6:
                commands[device].insert(1, f"delete protocols bgp group underlay_v6")

        # Add common config and interface configs
        commands[device].extend(generate_common_config(use_ipv4, use_ipv6))
        for interface, ip_data in interfaces.items():
            if interface not in skip_interfaces:  # Ensure "Unknown" and other skipped interfaces are not configured
                ipv4_address = ip_data.get("ipv4") if use_ipv4 else None
                ipv6_address = ip_data.get("ipv6") if use_ipv6 else None
                logging.info(f"Generating config for interface {interface}: IPv4: {ipv4_address}, IPv6: {ipv6_address}")
                commands[device].extend(generate_interface_group_config(interface, ipv4_address, ipv6_address))

        # Remove duplicate commands before logging or further usage
        commands[device] = remove_duplicates(commands[device])
        logging.info(f"commands for {device}: {commands[device]}")

'''def generate_config(commands, connections, local_as_mapping, delete_underlay_group, use_ipv4, use_ipv6, ip_assignments=None):
    ip_assignments = ip_assignments or {}
    configured_groups = set()  # Track which BGP groups have been configured
    skip_interfaces = {'re0:mgmt-0', 'em0', 'fxp0'}
    skip_device_patterns = ['mgmt', 'management', 'hypercloud']
    configured_interfaces = {}
    subnet_counter = 1  # Use subnet counter at the connection level

    def get_ip(subnet, host_id, ipv6=False):
        if ipv6:
            return f"fd00:{subnet}::{host_id}"
        else:
            return f"192.168.{subnet}.{host_id}"

    def get_subnet(ip_address, ipv6=False):
        if ipv6:
            return ipaddress.ip_network(ip_address + '/64', strict=False)
        else:
            return ipaddress.ip_network(ip_address + '/30', strict=False)

    def generate_bgp_group_config(group_name, use_ipv4=True, use_ipv6=False):
        commands = []
        # Add family inet unicast for IPv4 group
        if use_ipv4 and group_name == "underlay_v4":
            commands.append(f"set protocols bgp group {group_name} family inet unicast")

        # Add family inet6 unicast for IPv6 group
        if use_ipv6 and group_name == "underlay_v6":
            commands.append(f"set protocols bgp group {group_name} family inet6 unicast")

        return commands

    def generate_interface_group_config(interface, ipv4_address=None, ipv6_address=None):
        config_commands = [f"delete interfaces {interface}"]
        logging.info(f"Configuring interface {interface} with addresses: IPv4: {ipv4_address}, IPv6: {ipv6_address}")

        # For IPv4, use /30 prefix length
        if ipv4_address:
            config_commands.append(f"set interfaces {interface} unit 0 family inet address {ipv4_address}/30")

        # For IPv6, use /64 prefix length
        if ipv6_address:
            config_commands.append(f"set interfaces {interface} unit 0 family inet6 address {ipv6_address}/64")

        return config_commands

    def generate_bgp_neighbor_config(local_ip, neighbor_ip, local_as, remote_as, group_name):
        return [
            "## BGP Neighbor Config ##",
            f"set protocols bgp group {group_name} neighbor {neighbor_ip} peer-as {remote_as}",
            f"set protocols bgp group {group_name} neighbor {neighbor_ip} local-address {local_ip}",
            f"set protocols bgp group {group_name} local-as {local_as}"
        ]

    def remove_duplicates(commands_list):
        seen = set()
        result = []
        for command in commands_list:
            if command not in seen:
                seen.add(command)
                result.append(command)
        return result

    logging.info(f"connections: {connections}")

    # Process each connection and assign the same subnet for all devices in the connection
    for connection in connections:
        print(f"CSV Connection: {connection}")
        subnet = subnet_counter  # Use a single subnet per connection
        subnet_counter += 1
        host_id = 1  # Reset host_id for each connection
        neighbor_ip_mapping = {}

        # First loop: Assign IP addresses to devices and populate neighbor_ip_mapping
        if isinstance(connection, dict):
            for device, interface in connection.items():
                if any(pattern in device.lower() for pattern in skip_device_patterns) or interface in skip_interfaces:
                    continue
                if device not in ip_assignments:
                    ip_assignments[device] = {}
                if device not in configured_interfaces:
                    configured_interfaces[device] = set()
                if interface not in ip_assignments[device]:
                    ip_assignments[device][interface] = {}
                if interface not in configured_interfaces[device]:
                    # Assign IP addresses from the same subnet for devices in the connection
                    ipv4_address, ipv6_address = None, None
                    if use_ipv4:
                        ipv4_address = get_ip(subnet, host_id, ipv6=False)
                        ip_assignments[device][interface] = {"ipv4": ipv4_address}
                        neighbor_ip_mapping[f"{device}-{interface}-ipv4"] = ipv4_address
                    if use_ipv6:
                        ipv6_address = get_ip(subnet, host_id, ipv6=True)
                        ip_assignments[device][interface]["ipv6"] = ipv6_address
                        neighbor_ip_mapping[f"{device}-{interface}-ipv6"] = ipv6_address

                    configured_interfaces[device].add(interface)

                    # Increment host_id for each device in the connection
                    host_id += 1

            # Debugging: Print neighbor_ip_mapping only if it's not empty
            if neighbor_ip_mapping:
                print(f"Neighbor IP mapping after first loop: {neighbor_ip_mapping}")
                logging.info(f"Neighbor IP mapping after first loop: {neighbor_ip_mapping}")

        logging.info(f"Neighbor IP Mapping: {neighbor_ip_mapping}")

        # Second loop: Use the populated neighbor_ip_mapping to create BGP configurations
        for device, interface in connection.items():
            for ip_version in ["ipv4", "ipv6"]:
                if ip_version == "ipv4" and not use_ipv4:
                    continue
                if ip_version == "ipv6" and not use_ipv6:
                    continue

                if f"{device}-{interface}-{ip_version}" not in neighbor_ip_mapping:
                    # Skip if the interface was not assigned an IP address in the first loop
                    continue

                local_subnet = get_subnet(neighbor_ip_mapping[f"{device}-{interface}-{ip_version}"], ipv6=(ip_version == "ipv6"))

                for remote_device, remote_interface in connection.items():
                    if remote_device != device and f"{remote_device}-{remote_interface}-{ip_version}" in neighbor_ip_mapping:
                        remote_subnet = get_subnet(neighbor_ip_mapping[f"{remote_device}-{remote_interface}-{ip_version}"], ipv6=(ip_version == "ipv6"))
                        if local_subnet == remote_subnet:
                            local_as = local_as_mapping.get(device)
                            remote_as = local_as_mapping.get(remote_device)

                            if local_as is not None and remote_as is not None:
                                neighbor_ip = neighbor_ip_mapping[f"{remote_device}-{remote_interface}-{ip_version}"]
                                local_ip = neighbor_ip_mapping[f"{device}-{interface}-{ip_version}"]

                                # Select BGP group name based on IP version
                                group_name = "underlay_v4" if ip_version == "ipv4" else "underlay_v6"

                                # Configure BGP group if not already done
                                if group_name not in configured_groups:
                                    group_commands = generate_bgp_group_config(group_name,
                                                                               use_ipv4=(ip_version == "ipv4"),
                                                                               use_ipv6=(ip_version == "ipv6"))
                                    commands[device].extend(group_commands)
                                    configured_groups.add(group_name)

                                # Generate BGP neighbor configuration for the device
                                bgp_commands = generate_bgp_neighbor_config(local_ip, neighbor_ip, local_as, remote_as, group_name)
                                commands[device].extend(bgp_commands)

    # Add common and interface configurations
    for device, interfaces in ip_assignments.items():
        if any(pattern in device.lower() for pattern in skip_device_patterns):
            continue
        if device not in commands:
            commands[device] = []
        if delete_underlay_group:
            if use_ipv4:
                commands[device].insert(0, f"delete protocols bgp group underlay_v4")
            if use_ipv6:
                commands[device].insert(1, f"delete protocols bgp group underlay_v6")

        # Add common config and interface configs
        commands[device].extend(generate_common_config(use_ipv4, use_ipv6))
        for interface, ip_data in interfaces.items():
            if use_ipv4:
                ipv4_address = ip_data.get("ipv4")
            if use_ipv6:
                ipv6_address = ip_data.get("ipv6")
            logging.info(f"Generating config for interface {interface}: IPv4: {ipv4_address}, IPv6: {ipv6_address}")
            commands[device].extend(generate_interface_group_config(interface, ipv4_address, ipv6_address))

        # Remove duplicate commands before logging or further usage
        commands[device] = remove_duplicates(commands[device])
        logging.info(f"commands: {device}: {commands[device]}")
'''

"""def check_device_health(router_details, devices):
    health_status = {}
    for device in devices:
        device_id = device['id']
        device_ip = device['label']  # Assuming the label contains the IP address

        # Find the corresponding router details
        router_detail = next((rd for rd in router_details if rd['hostname'] == device_id), None)
        if not router_detail:
            health_status[device_id] = 'unknown'
            continue
        try:
            with Device(host=device_ip, user=router_detail['username'], passwd=router_detail['password'],
                        port=22) as dev:
                if dev.connected:
                    health_status[device_id] = 'reachable'
                else:
                    health_status[device_id] = 'unreachable'
        except ConnectAuthError as e:
            health_status[device_id] = 'auth_error'
            logging.info(f"Authentication error connecting to {device_ip}: {e}")
        except ConnectError as e:
            health_status[device_id] = 'connect_error'
            logging.info(f"Connection error to {device_ip}: {e}")
        except Exception as e:
            health_status[device_id] = 'unreachable'
            logging.info(f"Error connecting to {device_ip}: {e}")

    return health_status

    # Function to check link health"""


def check_device_health(router_details, devices, use_hostname_as_label=False):
    health_status = {}

    for device in devices:
        if use_hostname_as_label:
            device_id = device['ip']  # Use IP as device_id
            device_ip = device['hostname']  # Use hostname as the label
        else:
            device_id = device['id']  # Default behavior: Use device id
            device_ip = device['label']  # Use the label as IP address

        # Find the corresponding router details
        if use_hostname_as_label:
            router_detail = next((rd for rd in router_details if rd['hostname'] == device['hostname']), None)
        else:
            router_detail = next((rd for rd in router_details if rd['hostname'] == device_id), None)

        if not router_detail:
            health_status[device_id] = 'unknown'
            continue

        try:
            with Device(host=device_ip, user=router_detail['username'], passwd=router_detail['password'],
                        port=22) as dev:
                if dev.connected:
                    health_status[device_id] = 'reachable'
                else:
                    health_status[device_id] = 'unreachable'
        except ConnectAuthError as e:
            health_status[device_id] = 'auth_error'
            logging.info(f"Authentication error connecting to {device_ip}: {e}")
        except ConnectError as e:
            health_status[device_id] = 'connect_error'
            logging.info(f"Connection error to {device_ip}: {e}")
        except Exception as e:
            health_status[device_id] = 'unreachable'
            logging.info(f"Error connecting to {device_ip}: {e}")

    return health_status


def check_link_health(router_details, edges):
    health_status = {}
    for edge in edges:
        edge_id = edge['data']['id']
        logging.info(f"Processing edge: {edge_id}")

        try:
            source_device, source_interface, target_device, target_interface = edge_id.split('--')
        except ValueError as e:
            logging.error(f"Invalid edge_id format: {edge_id}, error: {e}")
            health_status[edge_id] = 'unknown'
            continue

        # Find the corresponding router details
        source_detail = next((rd for rd in router_details if rd['hostname'] == source_device), None)
        target_detail = next((rd for rd in router_details if rd['hostname'] == target_device), None)

        if not source_detail or not target_detail:
            health_status[edge_id] = 'unknown'
            continue

        try:
            with Device(host=source_detail['ip'], user=source_detail['username'], passwd=source_detail['password'],
                        port=22) as dev:
                interface_statuses = dev.rpc.get_interface_information()
                interfaces = interface_statuses.findall('.//physical-interface')
                for interface in interfaces:
                    interface_name = interface.find('name').text.strip()
                    operational_status = interface.find('oper-status').text.strip()
                    if interface_name == source_interface:
                        # logging.info(f"{source_detail['ip']}: {interface_name} - {operational_status}")
                        if operational_status == 'up':
                            health_status[edge_id] = 'reachable'
                        else:
                            health_status[edge_id] = 'unreachable'
                        break
        except ConnectAuthError as e:
            health_status[edge_id] = 'auth_error'
            logging.info(f"Authentication error connecting to {source_detail['ip']} for edge {edge_id}: {e}")
        except ConnectError as e:
            health_status[edge_id] = 'connect_error'
            logging.info(f"Connection error to {source_detail['ip']} for edge {edge_id}: {e}")
        except Exception as e:
            health_status[edge_id] = 'unreachable'
            logging.info(f"Error checking link {edge_id}: {e}")

    logging.info(health_status)
    return health_status






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
                 num_vxlan_configs, overlay_service_type, leaf_base_as, spine_base_as, service_count, service_int_leaves, esi_lag_services,spine_tags,leaf_tags,GenerateOverlayBtn_State):
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


    def load_template(self, template_name):
        """
        Load a Jinja2 template from the templates/ConfigTemplates directory.
        """
        base_dir = os.path.abspath(os.path.dirname(__file__))
        templates_dir = os.path.join(base_dir, 'templates', 'ConfigTemplates')
        env = Environment(loader=FileSystemLoader(templates_dir))
        return env.get_template(template_name)


    '''def generate_spine_configs(self):
        """
        Generate configurations for spine devices with the same AS number using the Jinja2 template.
        """
        # Load the Jinja2 environment and template
        template_name = "spine_config_tmpl.j2"
        template = self.load_template(template_name)

        spine_configs = []
        overlay_as = self.spine_base_as  # Use the same AS for both spines and leaves

        for i, spine_ip in enumerate(self.spine_ips):
            # Prepare the data to be rendered in the template
            config_data = {
                'is_spine': True,
                'spine_ip': spine_ip,
                'spine_as': overlay_as,
                'leaf_ips': self.leaf_ips,
            }
            # Render the configuration from the template
            spine_config = template.render(config_data)
            spine_configs.append(spine_config.strip().split('\n'))
        print(spine_configs)
        return spine_configs'''

    '''def generate_spine_configs(self):
        """
        Generate configurations for spine devices with the same AS number using the Jinja2 template,
        including the leaf-specific VXLAN VNI list.
        """
        # Load the Jinja2 environment and template
        template_name = "spine_config_tmpl.j2"
        template = self.load_template(template_name)

        spine_configs = []
        overlay_as = self.spine_base_as  # Use the same AS for both spines and leaves

        # Generate VXLAN VNI lists for each leaf
        leaf_vxlan_vni_lists = []
        if self.overlay_service_type == 'vxlan_vlan_aware_t2_seamless_stitching':
            for leaf_index in range(len(self.leaf_ips)):
                vxlan_vni_list = []
                for i in range(self.service_count):
                    vxlan_vni = self.base_vxlan_vni + i + (leaf_index * 1000)  # Unique VNIs per leaf
                    vxlan_vni_list.append(vxlan_vni)
                leaf_vxlan_vni_lists.append(vxlan_vni_list)
        else:
            for leaf_index in range(len(self.leaf_ips)):
                vxlan_vni_list = []
                for i in range(self.service_count):
                    vxlan_vni = self.base_vxlan_vni + i
                    vxlan_vni_list.append(vxlan_vni)
                leaf_vxlan_vni_lists.append(vxlan_vni_list)

        for i, spine_ip in enumerate(self.spine_ips):
            # Prepare the data to be rendered in the template
            config_data = {
                'is_spine': True,
                'spine_ip': spine_ip,
                'spine_as': overlay_as,
                'leaf_ips': self.leaf_ips,
                'vxlan_vni_list': leaf_vxlan_vni_lists[i],  # Pass the corresponding leaf VXLAN VNI list
                'service_count': self.service_count,
                'base_vxlan_vlan_id': self.base_vxlan_vlan_id,
                'overlay_service_type': self.overlay_service_type,
                'enumerate': enumerate
            }

            # Render the configuration from the template
            spine_config = template.render(config_data)
            cleaned_config = "\n".join([line.strip() for line in spine_config.splitlines() if line.strip()])
            #spine_configs.append(cleaned_config)
            spine_configs.append(cleaned_config.strip().split('\n'))

        return spine_configs'''

    '''def generate_spine_configs(self):
        """
        Generate configurations for spine devices with the same AS number using the Jinja2 template,
        including the leaf-specific VXLAN VNI list and removing empty lines and spaces. Leaf-spine
        mappings are identified using tags.
        """
        # Load the Jinja2 environment and template
        template_name = "spine_config_tmpl.j2"
        template = self.load_template(template_name)

        spine_configs = []
        overlay_as = self.spine_base_as  # Use the same AS for both spines and leaves

        # Tagging mechanism for spines and leaves
        # Example: each spine will have a tag and leaves will map to them
        spine_leaf_mapping = {
            'spine_1': ['leaf_1'],  # Spine 1 handles Leaf 1
            'spine_2': ['leaf_2']  # Spine 2 handles Leaf 2
        }

        # Assuming each spine IP is mapped to a tag
        spine_tags = ['spine_1', 'spine_2']
        leaf_tags = ['leaf_1', 'leaf_2']

        # Generate VXLAN VNI lists for each leaf
        leaf_vxlan_vni_lists = []
        if self.overlay_service_type == 'vxlan_vlan_aware_t2_seamless_stitching':
            for leaf_index in range(len(self.leaf_ips)):
                vxlan_vni_list = []
                for i in range(self.service_count):
                    vxlan_vni = self.base_vxlan_vni + i + (leaf_index * 1000)  # Unique VNIs per leaf
                    vxlan_vni_list.append(vxlan_vni)
                leaf_vxlan_vni_lists.append(vxlan_vni_list)
        else:
            for leaf_index in range(len(self.leaf_ips)):
                vxlan_vni_list = []
                for i in range(self.service_count):
                    vxlan_vni = self.base_vxlan_vni + i
                    vxlan_vni_list.append(vxlan_vni)
                leaf_vxlan_vni_lists.append(vxlan_vni_list)

        for i, spine_ip in enumerate(self.spine_ips):
            spine_tag = spine_tags[i]  # Get the tag for the current spine
            associated_leaves = spine_leaf_mapping.get(spine_tag, [])  # Get the leaves associated with the spine

            # Prepare the data to be rendered in the template
            config_data = {
                'is_spine': True,
                'spine_ip': spine_ip,  # Passing dynamic spine IP
                'spine_as': overlay_as,
                'leaf_ips': self.leaf_ips,  # Passing leaf IPs
                'leaf_tags': leaf_tags,  # Passing leaf tags
                'spine_tag': spine_tag,  # Tag for this spine
                'associated_leaves': associated_leaves,  # Leaves associated with this spine
                'vxlan_vni_list': leaf_vxlan_vni_lists[i],  # Pass the corresponding leaf VXLAN VNI list
                'service_count': self.service_count,
                'base_vxlan_vlan_id': self.base_vxlan_vlan_id,
                'overlay_service_type': self.overlay_service_type,  # Pass the service type to the template
                'enumerate': enumerate
            }

            # Render the configuration from the template
            spine_config = template.render(config_data)

            # Clean up the configuration to remove extra spaces and blank lines
            cleaned_config = "\n".join([line.strip() for line in spine_config.splitlines() if line.strip()])
            spine_configs.append(cleaned_config.strip().split('\n'))
            #spine_configs.append(cleaned_config)

        return spine_configs'''

    def get_associated_leaves(self, spine_tag, leaf_tags):
        """
        This function returns the leaf tags that are associated with the given spine tag.
        It compares the spine tag with the leaf tags and returns a list of leaf tags that match the spine tag.
        """
        associated_leaves = [leaf_tag for leaf_tag in leaf_tags if leaf_tag == spine_tag]
        return associated_leaves

    '''def generate_spine_configs(self, spine_tags=None, leaf_tags=None):
        """
        Generate configurations for spine devices using the Jinja2 template.
        If overlay_service_type is 'vxlan_vlan_aware_t2_seamless_stitching', spine_tags and leaf_tags are required.
        """

        # Load the Jinja2 environment and template
        template_name = "spine_config_tmpl.j2"
        template = self.load_template(template_name)

        spine_configs = []
        overlay_as = self.spine_base_as  # Use the same AS for both spines and leaves
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
                'enumerate': enumerate
            }

            # If overlay_service_type is 'vxlan_vlan_aware_t2_seamless_stitching', handle tag matching
            if self.overlay_service_type == 'vxlan_vlan_aware_t2_seamless_stitching':
                if spine_tags is None or leaf_tags is None:
                    raise ValueError("Spine and leaf tags are required for 'vxlan_vlan_aware_t2_seamless_stitching'")

                spine_tag = spine_tags[i]  # Get the tag for the current spine
                associated_leaves = self.get_associated_leaves(spine_tag,
                                                               leaf_tags)  # Get the leaves that match this spine tag

                # Initialize vxlan_vni_list for the associated leaves for this spine
                vxlan_vni_list = [None] * len(self.leaf_ips)  # Initialize list with None for each leaf index
                for leaf_index, leaf_tag in enumerate(leaf_tags):
                    if leaf_tag in associated_leaves:  # Check if the leaf is associated with the current spine
                        leaf_vni_list = []
                        for j in range(self.service_count):
                            vxlan_vni = self.base_vxlan_vni + j + (leaf_index * 1000)  # Unique VNIs per leaf
                            leaf_vni_list.append(vxlan_vni)
                        vxlan_vni_list[leaf_index] = leaf_vni_list  # Assign the VNI list to the correct leaf index

                config_data['spine_tag'] = spine_tag
                config_data['leaf_tags'] = leaf_tags
                config_data['associated_leaves'] = associated_leaves
                config_data['vxlan_vni_list'] = vxlan_vni_list  # Pass the VNIs of associated leaves
            # Render the configuration from the template
            spine_config = template.render(config_data)

            # Clean up the configuration to remove extra spaces and blank lines
            cleaned_config = "\n".join([line.strip() for line in spine_config.splitlines() if line.strip()])
            spine_configs.append(cleaned_config.strip().split('\n'))

        return spine_configs'''

    '''def generate_spine_configs(self, spine_tags=None, leaf_tags=None):
        """
        Generate configurations for spine devices using the Jinja2 template.
        If overlay_service_type is 'vxlan_vlan_aware_t2_seamless_stitching', spine_tags and leaf_tags are required.
        """

        # Load the Jinja2 environment and template
        template_name = "spine_config_tmpl.j2"
        template = self.load_template(template_name)

        spine_configs = []
        overlay_as = self.spine_base_as  # Use the same AS for both spines and leaves

        # Ensure both spine_tags and leaf_tags are provided if required
        if self.overlay_service_type == 'vxlan_vlan_aware_t2_seamless_stitching':
            if spine_tags is None or leaf_tags is None:
                raise ValueError("Spine and leaf tags are required for 'vxlan_vlan_aware_t2_seamless_stitching'")

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
                'enumerate': enumerate
            }

            if self.overlay_service_type == 'vxlan_vlan_aware_t2_seamless_stitching':
                spine_tag = spine_tags[i]  # Get the tag for the current spine

                # Initialize vxlan_vni_list for the associated leaves for this spine
                vxlan_vni_list = [None] * len(self.leaf_ips)  # Initialize list with None for each leaf index
                esi_map = {}  # Map for storing ESI values

                for leaf_index, leaf_tag in enumerate(leaf_tags):
                    if leaf_tag in spine_tags:  # If the leaf tag is in the spine tag list, associate it
                        leaf_vni_list = []
                        for j in range(self.service_count):
                            vxlan_vni = self.base_vxlan_vni + j + (leaf_index * 1000)  # Unique VNIs per leaf
                            leaf_vni_list.append(vxlan_vni)
                        vxlan_vni_list[leaf_index] = leaf_vni_list  # Assign the VNI list to the correct leaf index

                        # ESI Generation: Check if spine tags match
                        if spine_tags[i] == leaf_tag:  # If spine and leaf tags match, use static ESI
                            esi_map[leaf_index] = '00:00:22:22:22:22:22:22:22:22'
                        else:
                            # Generate unique ESI based on spine IP and VLAN ID if tags don't match
                            spine_ip_parts = spine_ip.split('.')
                            spine_ip_last_two = '%02X:%02X' % (int(spine_ip_parts[2]), int(spine_ip_parts[3]))
                            vlan_hex = '%02X' % (self.base_vxlan_vlan_id % 256)
                            esi_map[leaf_index] = '00:00:' + spine_ip_last_two + ':' + vlan_hex + ':22:22:22:22:22'

                # Add the necessary data to the config for rendering
                config_data['spine_tag'] = spine_tag
                config_data['leaf_tags'] = leaf_tags
                config_data['vxlan_vni_list'] = vxlan_vni_list  # Pass the VNIs of associated leaves
                config_data['esi_map'] = esi_map  # Pass the ESI map to the template

            # Render the configuration from the template
            spine_config = template.render(config_data)

            # Clean up the configuration to remove extra spaces and blank lines
            cleaned_config = "\n".join([line.strip() for line in spine_config.splitlines() if line.strip()])
            spine_configs.append(cleaned_config.strip().split('\n'))

        return spine_configs'''

    '''def generate_leaf_configs(self,spine_tags=None, leaf_tags=None):
        """
        Generate configurations for leaf devices with the same AS number.
        """

        def generate_overlay_vxlan_config(leaf_ip, leaf_index):
            """
            Generate VXLAN configuration for a specific leaf device based on the number of service counts.
            """

            def generate_service_ip(service_count, leaf_index):
                """
                Generate IPs for each service with handling for third and second octet overflow.
                """
                second_octet = self.base_ip_parts[1]
                third_octet = 0
                service_ips = []

                for i in range(service_count):
                    # Ensure third octet increments correctly
                    if third_octet > 254:
                        third_octet = 0
                        second_octet += 1  # Increment second octet on third octet overflow
                        if second_octet > 254:
                            raise ValueError("Second octet exceeded 254, IP range exhausted.")

                    # Construct the IP address using base parts and leaf_index for uniqueness
                    service_ip_address = f"{self.base_ip_parts[0]}.{second_octet}.{third_octet}.{leaf_index}"
                    service_ips.append(service_ip_address)
                    third_octet += 1

                return service_ips

            # Generate service IPs for the current leaf
            service_ips = generate_service_ip(self.service_count, leaf_index)

            # Generate service IPs for all other leaves
            other_service_ips_list = []
            for other_leaf_index, other_leaf_ip in enumerate(self.leaf_ips):
                if other_leaf_index != leaf_index:  # Skip the current leaf itself
                    other_service_ips_list.append(generate_service_ip(self.service_count, other_leaf_index))

            # Flatten the list of service IPs for other leaves and match them per VLAN
            other_service_ips_per_vlan = [
                [ips[vlan_index] for ips in other_service_ips_list]
                for vlan_index in range(self.service_count)
            ]

            # VXLAN VNI Generation Logic
            vxlan_vni_list = []
            if self.overlay_service_type == 'vxlan_vlan_aware_t2_seamless_stitching':
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
                'type5_vxlan': 'vxlan_type5_template.j2',
                'vxlan_type2_to_sym_type2_stitching': 'vxlan_type2_to_sym_type2_stitching.j2',
                'vxlan_type2_to_sym_type5': 'vxlan_type2_to_sym_type5_tmpl.j2',
                'vxlan_bgp_over_sym_type5': 'vxlan_bgp_over_sym_type5_tmpl.j2',
                'vxlan_vlan_aware_t2_seamless_stitching': 'vxlan_vlan_aware_t2_seamless_stitching.j2'
            }

            template_name = template_map.get(self.overlay_service_type)
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
                'service_int_leaves': self.service_int_leaves,
                'esi_lag_services': self.esi_lag_services,
                'other_service_ips_per_vlan': other_service_ips_per_vlan,
                'enumerate': enumerate
            }

            # Load and render the Jinja2 template
            template = self.load_template(template_name)
            rendered_config = template.render(context)

            # Clean and return the configuration
            cleaned_lines = [line.strip() for line in rendered_config.splitlines() if line.strip()]
            return "\n".join(cleaned_lines)

        def generate_leaf_bgp_config(device_ip, device_as, neighbor_ips):
            """
            Helper function to generate common BGP configuration.
            """
            config = [
                f"set interfaces lo0.0 family inet address {device_ip} primary preferred",
                f"set routing-options router-id {device_ip}",
                f"set routing-options autonomous-system {device_as}",
                f"set protocols bgp group overlay type internal",
                f"set protocols bgp group overlay local-address {device_ip}",
                f"set protocols bgp group overlay family evpn signaling"
            ]
            for neighbor_ip in neighbor_ips:
                peer_as = self.spine_base_as  # Use peer spine AS
                config.append(f"set protocols bgp group overlay neighbor {neighbor_ip}")
            return config
        leaf_configs = []
        overlay_as = self.spine_base_as  # Use the same AS for both spines and leaves
        for j, leaf_ip in enumerate(self.leaf_ips):
            # Generate BGP config for the leaf
            leaf_config = generate_leaf_bgp_config(leaf_ip, overlay_as, self.spine_ips)
            # Generate VXLAN overlay config for the leaf and append it
            vxlan_config = generate_overlay_vxlan_config(leaf_ip, j)
            leaf_config.append(vxlan_config)  # Append as a string, not a list
            # Append final config to list
            leaf_configs.append(leaf_config)
        return leaf_configs'''

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

            def generate_service_ip(service_count, leaf_index,service_type):
                """
                Generate IPs for each service with handling for third and second octet overflow.
                """
                second_octet = self.base_ip_parts[1]
                third_octet = 0
                service_ips = []

                for i in range(service_count):
                    # Ensure third octet increments correctly
                    if third_octet > 254:
                        third_octet = 0
                        second_octet += 1  # Increment second octet on third octet overflow
                        if second_octet > 254:
                            raise ValueError("Second octet exceeded 254, IP range exhausted.")
                            # If service type is 'type5_vxlan', generate service IPs in a different subnet
                    if second_octet > 254:
                        second_octet = 0
                        third_octet += 1  # Increment second octet on third octet overflow
                        if third_octet > 254:
                            raise ValueError("Second octet exceeded 254, IP range exhausted.")
                            # If service type is 'type5_vxlan', generate service IPs in a different subnet

                    if service_type == 'type5_vxlan':
                        # Move to the next subnet by incrementing the second octet
                        service_ip_address = f"{self.base_ip_parts[0]}.{second_octet}.{third_octet}.{self.last_octet}"
                        service_ips.append(service_ip_address)
                        second_octet += 1
                         # Construct the IP address using base parts and leaf_index for uniqueness
                    else:
                        service_ip_address = f"{self.base_ip_parts[0]}.{second_octet}.{third_octet}.{leaf_index}"
                        service_ips.append(service_ip_address)
                    third_octet += 1

                return service_ips

            # Generate service IPs for the current leaf
            service_ips = generate_service_ip(self.service_count, leaf_index,self.overlay_service_type)

            # Generate service IPs for all other leaves
            other_service_ips_list = []
            for other_leaf_index, other_leaf_ip in enumerate(self.leaf_ips):
                if other_leaf_index != leaf_index:  # Skip the current leaf itself
                    other_service_ips_list.append(generate_service_ip(self.service_count, other_leaf_index,self.overlay_service_type))

            # Flatten the list of service IPs for other leaves and match them per VLAN
            other_service_ips_per_vlan = [
                [ips[vlan_index] for ips in other_service_ips_list]
                for vlan_index in range(self.service_count)
            ]
            # VXLAN VNI Generation Logic
            vxlan_vni_list = []
            if self.overlay_service_type == 'vxlan_vlan_aware_t2_seamless_stitching':
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
                'type5_vxlan': 'vxlan_type5_template.j2',
                'vxlan_type2_to_sym_type2_stitching': 'vxlan_type2_to_sym_type2_stitching.j2',
                'vxlan_type2_to_sym_type5': 'vxlan_type2_to_sym_type5_tmpl.j2',
                'vxlan_bgp_over_sym_type5': 'vxlan_bgp_over_sym_type5_tmpl.j2',
                'vxlan_vlan_aware_t2_seamless_stitching': 'vxlan_vlan_aware_t2_seamless_stitching.j2',
                'leaf_config':'leaf_config_tmpl.j2'
            }

            template_name = template_map.get(self.overlay_service_type)
            leaf_template_name=template_map.get("leaf_config")
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
                'service_int_leaves': self.service_int_leaves,
                'esi_lag_services': self.esi_lag_services,
                'other_service_ips_per_vlan': other_service_ips_per_vlan,
                'enumerate': enumerate,
                'overlay_as': self.spine_base_as,  # Include AS number
                'spine_ips': self.spine_ips,  # Include spine IPs for BGP neighbors
                'GenerateOverlayBtn_State': self.GenerateOverlayBtn_State,
            }
            # Conditionally include 'leaf_tags' if required by the service type
            if leaf_tags is not None:
                context['leaf_tags'] = leaf_tags
            if spine_tags is not None:
                # Prepare spine IPs and tags for BGP neighbors, checking for matching spine and leaf tags
                spine_ips_with_tags = [(spine_ip, spine_tag) for spine_ip, spine_tag in zip(self.spine_ips, spine_tags)]
                context['spine_ips_with_tags'] = spine_ips_with_tags
            # Load and render the Jinja2 template
            template = self.load_template(template_name)
            leaf_template=self.load_template(leaf_template_name)
            rendered_leaf_config=leaf_template.render(context)
            rendered_config = template.render(context)
            cleaned_leaf_config_lines = [line.strip() for line in rendered_leaf_config.splitlines() if line.strip()]
            # Clean and return the configuration
            cleaned_lines = [line.strip() for line in rendered_config.splitlines() if line.strip()]
            cleaned_lines.append(cleaned_leaf_config_lines)
            #return cleaned_lines
            return cleaned_leaf_config_lines

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
                if service_type == 'type5_vxlan':
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
                if service_type == 'type5_vxlan':
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
            print(f"v6_service_ips: {v6_service_ips}")
            print(f"service_ips: {service_ips}")
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
                'type5_vxlan': 'vxlan_type5_template.j2',
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

