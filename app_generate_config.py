
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, current_app, jsonify, send_from_directory
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.utils.sw import SW
from lxml import etree
from flask_socketio import SocketIO, emit
import logging
from logging.handlers import RotatingFileHandler
import os, io
import csv
import time
from collections import defaultdict
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_migrate import Migrate
import ipaddress
from flask import session
import threading
from datetime import datetime
from jnpr.junos.exception import ConnectError, ConnectAuthError, ConfigLoadError, CommitError, LockError, UnlockError
from werkzeug.utils import secure_filename
from jnpr.junos.utils.scp import SCP
from flask_socketio import emit
import asyncio
from threading import Thread, Event
import hashlib
from jnpr.junos.exception import RpcTimeoutError
import websockets
from flask_cors import CORS


app = Flask(__name__)
CORS(app)
socketio = SocketIO(app)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
logging.basicConfig(level=logging.INFO)

app.config['SESSION_TYPE'] = 'filesystem'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
stop_event = Event()
stop_events = {}



# Initialize Flask-Migrate
migrate = Migrate(app, db)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')


class TriggerEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(150), nullable=False)
    iteration = db.Column(db.Integer, nullable=False)
    device_name = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    command = db.Column(db.Text, nullable=True)

class DeviceInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    hostname = db.Column(db.String(150), nullable=False)
    ip = db.Column(db.String(150), nullable=False, unique=True)
    username = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('devices', lazy=True))

class Topology(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    csv_data = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('topologies', lazy=True))


def get_router_details_from_db():
    router_details = []
    devices = DeviceInfo.query.all()
    for device in devices:
        router_details.append({
            'hostname': device.hostname,
            'ip': device.ip,
            'username': device.username,
            'password': device.password
        })
    return router_details

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
    return user_folder, log_folder

def setup_user_logging(username):
    log_folder = os.path.join('logs', username)
    log_file_path = os.path.join(log_folder, 'debug.log')
    handler = RotatingFileHandler(log_file_path, maxBytes=1000000, backupCount=1)
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    if logger.hasHandlers():
        logger.handlers.clear()
    logger.addHandler(handler)
    return logger


## Code used for user topology  ##


@app.route('/generate_lldp_connections', methods=['POST'])
@login_required
def generate_lldp_connections():
    devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
    logging.info(f"Devices found: {devices}")
    if not devices:
        logging.info(f"No devices found for user {current_user.id}")
        return jsonify({'error': 'No devices found'}), 404

    neighbors_dict = defaultdict(list)
    for device in devices:
        hostname = device.hostname
        router_ip = device.ip
        router_user = device.username
        router_password = device.password
        logging.info(f"Attempting to connect to device: {hostname} at IP: {router_ip}")
        try:
            with Device(host=router_ip, user=router_user, passwd=router_password, port=22) as dev:
                logging.info(f"Successfully connected to {hostname}")
                neighbors = dev.rpc.get_lldp_neighbors_information()
                logging.info(f"LLDP neighbors information for {hostname}: {etree.tostring(neighbors, pretty_print=True).decode('utf-8')}")
                for neighbor in neighbors.findall('.//lldp-neighbor-information'):
                    interface = neighbor.find('lldp-local-port-id').text.strip()
                    remote_system_name = neighbor.find('lldp-remote-system-name').text.strip()
                    remote_port_desc = neighbor.find('lldp-remote-port-description').text.strip()

                    if remote_system_name and remote_port_desc:
                        logging.info(f"Neighbor found - Interface: {interface}, Remote System Name: {remote_system_name}, Remote Port Desc: {remote_port_desc}")
                        neighbors_dict[hostname].append((remote_system_name, interface, remote_port_desc))
        except Exception as e:
            logging.error(f"Failed to fetch LLDP neighbors for {hostname}: {e}")

    if not neighbors_dict:
        logging.info("No LLDP neighbors found for any device.")
        return jsonify({'error': 'No LLDP neighbors found'}), 404

    trim_domain_neighbors = simplified_neighbors_dict(neighbors_dict)
    connections = []
    for key, values in trim_domain_neighbors.items():
        for value in values:
            connection = {
                key: value[1],
                value[0]: value[2]
            }
            connections.append(connection)

    unique_connections = []
    seen = set()
    for connection in connections:
        # Convert each connection to a tuple of sorted items to handle bidirectional connections
        sorted_connection = tuple(sorted(connection.items()))
        if sorted_connection not in seen:
            seen.add(sorted_connection)
            unique_connections.append(connection)
    logging.info(f"LLDP Neighbors Connections: {unique_connections}")
    csv_content = "Device1,Interface1,Device2,Interface2\n"
    for connection in unique_connections:
        device1 = list(connection.keys())[0]
        interface1 = connection[device1]
        device2 = list(connection.keys())[1]
        interface2 = connection[device2]
        csv_content += f"{device1},{interface1},{device2},{interface2}\n"
    logging.info(f"Saveing LLDP neighbors to user database: {csv_content}")
    topology = Topology(user_id=current_user.id, csv_data=str(csv_content))
    db.session.add(topology)
    db.session.commit()
    logging.info('Saved topology to database for user: %s', current_user.username)
    return jsonify({'success': True, 'connections': csv_content})

@app.route('/save_topo_csv', methods=['POST'])
@login_required
def save_topo_csv():
    if 'file' not in request.files:
        logging.error('No file part in the request')
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        logging.error('No selected file')
        return jsonify({'error': 'No selected file'}), 400
    filename = file.filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    logging.info('Saved file to %s', filepath)
    # Read the file content
    file.seek(0)
    csv_file = io.StringIO(file.read().decode('utf-8'), newline=None)
    csv_reader = csv.DictReader(csv_file)
    csv_data = 'Device1,Interface1,Device2,Interface2\n' + '\n'.join([','.join(row.values()) for row in csv_reader])
    logging.info('Parsed CSV data: %s', csv_data)
    topology = Topology(user_id=current_user.id, csv_data=csv_data)
    db.session.add(topology)
    db.session.commit()
    logging.info('Saved topology to database for user: %s', current_user.username)
    return jsonify({'success': True})

@app.route('/get_my_topology', methods=['GET'])
@login_required
def get_my_topology():
    topology = Topology.query.filter_by(user_id=current_user.id).order_by(Topology.timestamp.desc()).first()

    if not topology:
        return jsonify({'error': 'No topology found'}), 404

    csv_data = topology.csv_data
    csv_file = io.StringIO(csv_data)
    csv_reader = csv.DictReader(csv_file)
    topology_list = []
    for row in csv_reader:
        topology_list.append({
            'Device1': row['Device1'],
            'Interface1': row['Interface1'],
            'Device2': row['Device2'],
            'Interface2': row['Interface2']
        })

    return jsonify({'topology': topology_list})

## END

## Device Health/SSH Test ##

@app.route('/initiate_ssh', methods=['POST'])
@login_required
def initiate_ssh():
    data = request.get_json()
    device_id = data.get('device_id')
    device_info = get_router_details_from_db(device_id)
    if device_info:
        ws_url = f"ws://localhost:8765/{device_id}"
        return jsonify({'success': True, 'ssh_url': ws_url})
    else:
        return jsonify({'success': False, 'error': 'Device not found'}), 404

async def ssh_handler(websocket, path):
    device_id = path.strip('/')
    device_info = get_router_details_from_db(device_id)  # Fetch device details from DB
    if not device_info:
        await websocket.send("Invalid device ID")
        return

    try:
        with Device(host=device_info['ip'], user=device_info['username'], passwd=device_info['password'], port=22) as dev:
            if dev.connected:
                await websocket.send(f"Connected to {device_id}\n")
                while True:
                    msg = await websocket.recv()
                    if msg == 'exit':
                        break
                    # Execute SSH command or interact with the device here
                    await websocket.send(f"Received command: {msg}\n")
            else:
                await websocket.send(f"Failed to connect to {device_id}")
    except Exception as e:
        await websocket.send(f"Error: {str(e)}")

def start_websocket_server():
    asyncio.set_event_loop(asyncio.new_event_loop())
    start_server = websockets.serve(ssh_handler, "localhost", 8760)
    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()

# Start WebSocket server in a new thread
"""websocket_thread = threading.Thread(target=start_websocket_server)
websocket_thread.start()
"""


# Function to check device health
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
            with Device(host=device_ip, user=router_detail['username'], passwd=router_detail['password'], port=22) as dev:
                if dev.connected:
                    health_status[device_id] = 'reachable'
                else:
                    health_status[device_id] = 'unreachable'
        except Exception as e:
            health_status[device_id] = 'unreachable'
            print(f"Error connecting to {device_ip}: {e}")

    return health_status"""

def check_device_health(router_details, devices):
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
            with Device(host=device_ip, user=router_detail['username'], passwd=router_detail['password'], port=22) as dev:
                if dev.connected:
                    health_status[device_id] = 'reachable'
                else:
                    health_status[device_id] = 'unreachable'
        except ConnectAuthError as e:
            health_status[device_id] = 'auth_error'
            print(f"Authentication error connecting to {device_ip}: {e}")
        except ConnectError as e:
            health_status[device_id] = 'connect_error'
            print(f"Connection error to {device_ip}: {e}")
        except Exception as e:
            health_status[device_id] = 'unreachable'
            print(f"Error connecting to {device_ip}: {e}")

    return health_status


# Function to check link health
"""def check_link_health(router_details, edges):
    health_status = {}
    #logging.info(edges)
    for edge in edges:
        edge_id = edge['data']['id']
        logging.info(f"Processing edge: {edge_id}")
        try:
            source_device, source_interface, target_device, target_interface = edge_id.split('--')
        except ValueError:
            logging.error(f"Invalid edge_id format: {edge_id}")
            health_status[edge_id] = 'unknown'
            continue

        # Find the corresponding router details
        source_detail = next((rd for rd in router_details if rd['hostname'] == source_device), None)
        target_detail = next((rd for rd in router_details if rd['hostname'] == target_device), None)

        if not source_detail or not target_detail:
            health_status[edge_id] = 'unknown'
            continue

        try:
            with Device(host=source_detail['ip'], user=source_detail['username'], passwd=source_detail['password'], port=22) as dev:
                interface_statuses = dev.rpc.get_interface_information()
                interfaces = interface_statuses.findall('.//physical-interface')
                for interface in interfaces:
                    interface_name = interface.find('name').text.strip()
                    operational_status = interface.find('oper-status').text.strip()
                    #print(interface_name, operational_status)
                    if interface_name == source_interface:
                        if operational_status == 'up':
                            health_status[edge_id] = 'reachable'
                        else:
                            health_status[edge_id] = 'unreachable'
                        break
        except Exception as e:
            health_status[edge_id] = 'unreachable'
            print(f"Error checking link {edge_id}: {e}")
    return health_status"""

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
            with Device(host=source_detail['ip'], user=source_detail['username'], passwd=source_detail['password'], port=22) as dev:
                interface_statuses = dev.rpc.get_interface_information()
                interfaces = interface_statuses.findall('.//physical-interface')
                for interface in interfaces:
                    interface_name = interface.find('name').text.strip()
                    operational_status = interface.find('oper-status').text.strip()
                    if interface_name == source_interface:
                        #logging.info(f"{source_detail['ip']}: {interface_name} - {operational_status}")
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


# Flask route to check device and link health
@app.route('/check_device_health', methods=['POST'])
@login_required
def check_health_route():
    data = request.get_json()
    devices = data.get('devices', [])
    edges = data.get('edges', [])
    router_details = get_router_details_from_db()
    device_health_status = check_device_health(router_details, devices)
    link_health_status = check_link_health(router_details, edges)
    health_status = {**device_health_status, **link_health_status}
    return jsonify({'health_status': health_status})


"""## Device online status check using ssh netconf port 22 ##
@app.route('/check_device_health', methods=['POST'])
@login_required
def check_device_health():
    data = request.get_json()
    devices = data.get('devices', [])
    health_status = {}
    router_details = get_router_details_from_db()
    for device in devices:
        device_id = device['id']
        device_ip = device['label']  # Assuming the label contains the IP address
        # Find the corresponding router details
        router_detail = next((rd for rd in router_details if rd['hostname'] == device_id), None)
        if not router_detail:
            health_status[device_id] = 'unknown'
            continue
        try:
            with Device(host=device_ip, user=router_detail['username'], passwd=router_detail['password'], port=22) as dev:
                if dev.connected:
                    health_status[device_id] = 'reachable'
                else:
                    health_status[device_id] = 'unreachable'
        except Exception as e:
            health_status[device_id] = 'unreachable'
            print(f"Error connecting to {device_ip}: {e}")

    return jsonify({'health_status': health_status})"""



#END


@app.route('/upload_csv', methods=['POST'])
def upload_csv():
    if 'UPLOAD_FOLDER' not in current_app.config:
        return jsonify(success=False, error='Please login again'), 401
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'})
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'File upload failed'})




@app.route('/install_image', methods=['POST'])
def install_image():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Please login again', 'error')
        return redirect(url_for('index'))

    def calculate_md5(file_path):
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    data = request.json
    logging.info('Received data: %s', data)
    if not data or 'imageName' not in data or 'deviceIds' not in data:
        return jsonify(success=False, error="Missing image name or device ID"), 400

    image_name = data['imageName']
    device_ids = data['deviceIds']
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
    logging.info('Image Name: %s', image_name)
    logging.info('Device IDs: %s', device_ids)

    if not image_name:
        return jsonify(success=False, error="Missing image name"), 400
    if not device_ids or not isinstance(device_ids, list) or not all(device_ids):
        return jsonify(success=False, error="Invalid device IDs"), 400
    if not os.path.exists(image_path):
        return jsonify(success=False, error="Image file not found"), 404

    image_size = os.path.getsize(image_path)  # Get image size in bytes
    image_md5 = calculate_md5(image_path)
    logging.info(f"image_name/image_md5: {image_name} / {image_md5}")
    errors = []
    successes = []

    def get_remote_md5(dev, remote_path):
        try:
            logging.info(f"Executing get_checksum_information RPC on remote device: {remote_path}")
            response = dev.rpc.get_checksum_information(path=remote_path)
            response_str = etree.tostring(response, pretty_print=True).decode()
            logging.info(f"Full get_checksum_information Response: {response_str}")
            checksum_output = response.findtext('.//checksum')
            if checksum_output:
                checksum_output = checksum_output.strip()  # Strip any whitespace
                logging.info(f"Remote MD5 checksum: {checksum_output}")
                return checksum_output
            else:
                logging.error("MD5 checksum not found in the response.")
        except Exception as e:
            logging.error(f"get_checksum_information RPC failed: {str(e)}")
        return None

    def scp_progress(filename, size, sent, device_id):
        if stop_events[device_id].is_set():
            raise Exception("Image copy stopped by user.")
        progress = int((sent / size) * 100)
        socketio.emit('install_progress', {'device_id': device_id, 'progress': progress, 'stage': 'copying'})

    def check_storage_space(dev, required_space):
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
            return False, None, None

    def myprogress(dev, report):
        logging.info("host: %s, report: %s" % (dev.hostname, report))
        if isinstance(report, dict) and report.get('transfer-status') is not None:
            try:
                progress = int(report.get('transfer-status').get('progress', 0))
            except (ValueError, TypeError):
                progress = 0
            socketio.emit('install_progress', {'device_id': dev.hostname, 'progress': progress, 'stage': 'installing'})
        elif isinstance(report, str):
            socketio.emit('install_progress',
                          {'device_id': dev.hostname, 'progress': 0, 'stage': 'installing', 'message': report})
        if isinstance(report, dict) and report.get('package') is not None:
            socketio.emit('install_progress', {'device_id': dev.hostname, 'progress': 100, 'stage': 'installing',
                                               'message': report.get('package')})

    def install_image_on_device(dev, remote_image_path):
        try:
            sw = SW(dev)
            logging.info(f"Remote Image path: {dev.hostname}, {remote_image_path}")
            ok, msg = sw.install(package=remote_image_path, validate=True, progress=myprogress, dev_timeout=2400,
                                 checksum_timeout=400, no_copy=True)
            if ok:
                logging.info('Image installed on %s successfully.', dev.hostname)
                sw.reboot()
                socketio.emit('install_progress', {'device_id': dev.hostname, 'progress': 100, 'stage': 'installing'})
                return True
            else:
                logging.error('Failed to install image on %s: %s', dev.hostname, msg)
                return False
        except Exception as e:
            logging.error('Error installing image on %s: %s', dev.hostname, str(e))
            return False

    def copy_image_to_device(device, image_path, image_size, device_id):
        try:
            logging.info('Connecting to device: %s', device.hostname)
            try:
                with Device(host=device.ip, user=device.username, passwd=device.password, port=22) as dev:
                    # Check storage space
                    storage_ok, avail_space, mount_point = check_storage_space(dev, image_size)
                    if not storage_ok:
                        error_message = f"Insufficient storage space on {device.hostname}. Required: {image_size} bytes, Available: {avail_space} bytes"
                        logging.error(error_message)
                        socketio.emit('install_progress',
                                      {'device_id': device_id, 'progress': 0, 'error': True, 'message': error_message})
                        errors.append(error_message)
                        return

                    remote_image_path = f"{mount_point}/{os.path.basename(image_path)}"
                    logging.info(f"Remote image path set to: {remote_image_path}")

                    remote_md5 = get_remote_md5(dev, remote_image_path)

                    if remote_md5:
                        if remote_md5 == image_md5:
                            message = f"Image already exists on {device.hostname} with matching MD5 checksum."
                            logging.info(message)
                            socketio.emit('install_progress',
                                          {'device_id': device_id, 'progress': 100, 'stage': 'copying',
                                           'message': message})
                            socketio.emit('image_status',
                                          {'device_id': device_id, 'status': 'exists', 'message': message})
                            successes.append(message)
                            # Start installation directly if the image already exists
                            install_success = install_image_on_device(dev, remote_image_path)
                            if install_success:
                                successes.append(f"Image installed on {device.hostname} successfully.")
                            else:
                                errors.append(f"Failed to install image on {device.hostname}.")
                            return
                        else:
                            logging.info(
                                f"Image exists on {device.hostname} but MD5 checksum differs. Proceeding to copy.")
                            socketio.emit('install_progress',
                                          {'device_id': device_id, 'progress': 0, 'stage': 'copying'})

                    # Perform the copy with retries on failure
                    for attempt in range(3):
                        try:
                            with SCP(dev, progress=lambda f, s, t: scp_progress(f, s, t, device_id)) as scp:
                                scp.put(image_path, remote_path=remote_image_path)
                            logging.info('Image copied to %s: %s successfully.', device.hostname, remote_image_path)
                            socketio.emit('install_progress',
                                          {'device_id': device_id, 'progress': 100, 'stage': 'copying'})
                            successes.append(f"Image copied to {device.hostname}:{remote_image_path} successfully.")
                            break
                        except Exception as e:
                            logging.error('Error copying image on attempt %d: %s', attempt + 1, str(e))
                            if attempt == 2:
                                socketio.emit('install_progress',
                                              {'device_id': device_id, 'progress': 0, 'error': True, 'message': str(e)})
                                errors.append(f"Error copying image to {device.hostname} after 3 attempts: {str(e)}")
                                return

                    # Verify MD5 checksum of the copied image
                    remote_md5 = get_remote_md5(dev, remote_image_path)
                    if remote_md5 == image_md5:
                        logging.info(f"MD5 checksum verification succeeded for {device.hostname}.")
                        install_success = install_image_on_device(dev, remote_image_path)
                        if install_success:
                            successes.append(f"Success! Image Copy on {device.hostname}.")
                        else:
                            errors.append(f"Fail! to Copy image on {device.hostname}.")
                    else:
                        error_message = f"MD5 checksum verification failed for {device.hostname}. Expected: {image_md5}, Got: {remote_md5}"
                        logging.error(error_message)
                        socketio.emit('install_progress',
                                      {'device_id': device_id, 'progress': 0, 'error': True, 'message': error_message})
                        errors.append(error_message)
            except ConnectAuthError as e:
                error_message = f"Authentication error connecting to {device.hostname}: {str(e)}"
                logging.error(error_message)
                socketio.emit('install_progress',
                              {'device_id': device_id, 'progress': 0, 'error': True, 'message': error_message})
                errors.append(error_message)
            except ConnectError as e:
                error_message = f"Connection error to {device.hostname}: {str(e)}"
                logging.error(error_message)
                socketio.emit('install_progress',
                              {'device_id': device_id, 'progress': 0, 'error': True, 'message': error_message})
                errors.append(error_message)
        except Exception as e:
            if str(e) == "Image copy stopped by user.":
                logging.info(f"Image {remote_image_path} copy process stopped for device {device.hostname}.")
                socketio.emit('install_progress', {'device_id': device_id, 'progress': 0, 'error': True,
                                                   'message': "Image copy process stopped."})
                errors.append(f"Image {remote_image_path} copy process stopped for {device.hostname}.")
            else:
                error_message = f"Error copying image {remote_image_path} to {device.hostname}: {str(e)}"
                logging.error(error_message)
                socketio.emit('install_progress',
                              {'device_id': device_id, 'progress': 0, 'error': True, 'message': error_message})
                errors.append(error_message)
    threads = []
    for device_id in device_ids:
        device = db.session.get(DeviceInfo, device_id)
        if not device:
            errors.append(f"Device ID {device_id} not found")
            continue
        stop_events[device_id] = threading.Event()
        thread = threading.Thread(target=copy_image_to_device, args=(device, image_path, image_size, device_id))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    if successes:
        return jsonify(success=True, successes=successes, errors=errors)
    else:
        if any("Image copy process stopped." in err for err in errors):
            return jsonify(success=False, errors=errors, message="Image copy process stopped.")
        return jsonify(success=False, errors=errors)


@app.route('/stop_image_copy', methods=['POST'])
def stop_image_copy():
    data = request.json
    device_id = data.get('device_id')
    if device_id and device_id in stop_events:
        stop_events[device_id].set()
        logging.info(f"Image copy process stopped for device {device_id}.")
        return jsonify(success=True, message=f"Image copy process stopped for device {device_id}.")
    return jsonify(success=False, error="Invalid device ID"), 400



@app.route('/upload_image', methods=['POST'])
@login_required
def upload_image():
    if 'UPLOAD_FOLDER' not in current_app.config:
        return jsonify(success=False, error='Please login again'), 401
    if 'UPLOAD_FOLDER' not in current_app.config:
        return jsonify(success=False, error='Please login again'), 401

    if 'imageFile' not in request.files:
        return jsonify(success=False, error='No file part'), 400

    file = request.files['imageFile']
    if file.filename == '':
        return jsonify(success=False, error='No selected file'), 400

    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        return jsonify(success=True), 200

    return jsonify(success=False, error='File not saved'), 500



@app.route('/fetch_images', methods=['GET'])
def fetch_images():
    if 'UPLOAD_FOLDER' not in current_app.config:
        return jsonify(success=False, error='Please login again'), 401
    try:
        files = os.listdir(app.config['UPLOAD_FOLDER'])
        images = [f for f in files if os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], f)) and 'install' in f.lower()]
        return jsonify(images)
    except Exception as e:
        return jsonify({'error': str(e)}), 500





@app.route('/uploaded_images', methods=['GET'])
def uploaded_images():
    if 'UPLOAD_FOLDER' not in current_app.config:
        return jsonify(success=False, error='Please login again'), 401
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    images = [file for file in files if allowed_file(file)]
    return jsonify(images)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'jpg', 'jpeg', 'png', 'gif'}


@app.route('/api/images', methods=['GET'])
@login_required
def get_uploaded_images():
    if 'UPLOAD_FOLDER' not in current_app.config:
        return jsonify(success=False, error='Please login again'), 401

    upload_folder = current_app.config['UPLOAD_FOLDER']
    try:
        images = os.listdir(upload_folder)
        return jsonify(success=True, images=images)
    except Exception as e:
        return jsonify(success=False, error=str(e)), 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


### this code is used for viewing the content of uploaded files ##
@app.route('/list_uploaded_images', methods=['GET'])
@login_required
def list_uploaded_images():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return jsonify({'files': files})

@app.route('/show_file_content', methods=['POST'])
@login_required
def show_file_content():
    filename = request.form['filename']
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(filepath):
        with open(filepath, 'r') as file:
            content = file.read()
        return jsonify({'content': content})
    return jsonify({'error': 'File not found'}), 404

@app.route('/save_file_content', methods=['POST'])
@login_required
def save_file_content():
    data = request.get_json()
    filename = data['filename']
    content = data['content']
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    try:
        with open(filepath, 'w') as file:
            file.write(content)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
## END



@app.route('/delete_image/<image_name>', methods=['DELETE'])
@login_required  # Ensure this decorator is only used if you have a login system set up
def delete_image(image_name):
    logging.info(f"Received request to delete image: {image_name}")

    if 'UPLOAD_FOLDER' not in current_app.config:
        return jsonify({'success': False, 'error': 'Please login again'}), 401

    user_folder = os.path.join(current_app.config['UPLOAD_FOLDER'])
    image_path = os.path.join(user_folder, image_name)

    logging.info(f"Full image path: {image_path}")

    if not os.path.exists(image_path):
        logging.error(f"Image file not found: {image_path}")
        return jsonify(success=False, error="Image file not found"), 404

    try:
        os.remove(image_path)
        logging.info(f"Successfully deleted image: {image_path}")
        return jsonify(success=True)
    except Exception as e:
        logging.error(f"Error deleting image {image_name}: {str(e)}")
        return jsonify(success=False, error=str(e)), 500


"""@app.route('/fetch_device_config/<int:device_id>', methods=['GET'])
@login_required
def fetch_device_config(device_id):
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Please login again', 'error')
        return jsonify({'success': False, 'error': 'Please login again'}), 401

    device = db.session.get(DeviceInfo, device_id)
    print(device)
    if not device:
        flash("Device not found", "error")
        return jsonify({"success": False, "message": "Device not found"}), 404

    try:
        dev = Device(host=device.ip, user=device.username, passwd=device.password, port=22)
        dev.open()
        config = dev.rpc.get_config(options={'format': 'set'})
        dev.close()
    except ConnectAuthError as e:
        logging.error(f"Connection authentication error for device {device.hostname}: {str(e)}")
        flash(f"Connection authentication error: {str(e)}", "error")
        return jsonify({"success": False, "message": f"Connection authentication error: {str(e)}"}), 500
    except ConnectError as e:
        logging.error(f"Connection error for device {device.hostname}: {str(e)}")
        flash(f"Connection error: {str(e)}", "error")
        return jsonify({"success": False, "message": f"Connection error: {str(e)}"}), 500
    except Exception as e:
        logging.error(f"Error fetching configuration for device {device.hostname}: {str(e)}")
        flash(f"Error: {str(e)}", "error")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

    config_data = {
        "success": True,
        "hostname": device.hostname,
        "config": config.text
    }

    logging.info(f"Configuration fetched successfully for device {device.hostname}")
    flash("Configuration fetched successfully.", "success")
    return jsonify(config_data)"""

@app.route('/fetch_device_config/<int:device_id>', methods=['GET'])
@login_required
def fetch_device_config(device_id):
    #print("I am here")
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Please login again', 'error')
        return jsonify({'success': False, 'error': 'Please login again'}), 401
    device = db.session.get(DeviceInfo, device_id)
    if not device:
        flash("Device not found", "error")
        return jsonify({"success": False, "message": "Device not found"}), 404
    try:
        with Device(host=device.ip, user=device.username, passwd=device.password, port=22) as dev:
            config = dev.rpc.get_config(options={'format': 'set'})
    except ConnectAuthError as e:
        logging.error(f"Connection authentication error for device {device.hostname}: {str(e)}")
        return jsonify({"success": False, "message": f"Connection authentication error: {str(e)}"}), 500
    except ConnectError as e:
        logging.error(f"Connection error for device {device.hostname}: {str(e)}")
        return jsonify({"success": False, "message": f"Connection error: {str(e)}"}), 500
    except Exception as e:
        logging.error(f"Error fetching configuration for device {device.hostname}: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

    config_data = {
        "success": True,
        "hostname": device.hostname,
        "config": config.text
    }

    logging.info(f"Configuration fetched successfully for device {device.hostname}")
    return jsonify(config_data)


@app.route('/save_device_config', methods=['POST'])
@login_required
def save_device_config():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Please login again', 'error')
        return jsonify({'success': False, 'error': 'Please login again'}), 401

    data = request.get_json()
    device_data = data.get('deviceData')
    config_data = data.get('configData')

    logging.info(f"Received device data: {device_data}")
    logging.info(f"Received config data: {config_data}")

    if not device_data or not config_data:
        logging.error('Missing device data or configuration data')
        return jsonify({'success': False, 'error': 'Missing device data or configuration data'})

    try:
        user_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], str(current_user.id))
        os.makedirs(user_folder, exist_ok=True)  # Ensure the directory exists

        config_filename = f"{device_data['hostname']}_config.txt"
        config_filepath = os.path.join(user_folder, config_filename)
        config_content = config_data['config']  # Use the correct key here

        with open(config_filepath, 'w') as config_file:
            config_file.write(config_content)

        logging.info(f"Config saved successfully for {device_data['hostname']} at {config_filepath}")
        return jsonify({'success': True})
    except Exception as e:
        logging.error(f"Error saving configuration for {device_data.get('hostname', 'unknown')}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/update_device_configuration/<int:device_id>', methods=['POST'])
def update_device_configuration(device_id):
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Please login again', 'error')
        return jsonify({'success': False, 'error': 'Please login again'}), 401
    config = request.json.get('config')
    # You would fetch these details from your database
    device = db.session.get(DeviceInfo, device_id)
    if not device:
        return jsonify({'success': False, 'error': 'Device not found'}), 404

    device_name = device.hostname
    router_ip = device.ip
    router_user = device.username
    router_password = device.password

    config_lines = config.split('\n')
    config_format="set"
    result = transfer_file_to_router(config_lines, router_ip, router_user, router_password, device_name,config_format)

    if "successfully" in result:
        return jsonify({'success': True, 'message': result})
    else:
        return jsonify({'success': False, 'error': result}), 500



@app.route('/update_device_config', methods=['POST'])
@login_required
def update_device_config():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Pls login again', 'error')
        return jsonify({'success': False, 'error': 'Please login again'}), 401
    data = request.get_json()
    device_id = data.get('id')
    new_username = data.get('username')
    new_password = data.get('password')

    device = db.session.get(DeviceInfo, device_id)
    if not device:
        return jsonify({'success': False, 'error': 'Device not found'}), 404

    try:
        device.username = new_username
        device.password = new_password
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


"""@app.route('/save_all_device_configs', methods=['POST'])
@login_required
def save_all_device_configs():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Pls login again', 'error')
        return jsonify({'success': False, 'error': 'Please login again'}), 401
    devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
    errors = []
    user_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], str(current_user.id))
    os.makedirs(user_folder, exist_ok=True)
    for device in devices:
        try:
            logging.info(f"Connecting to device {device.hostname} at {device.ip}")
            dev = Device(host=device.ip, user=device.username, passwd=device.password, port=22)
            dev.open()
            logging.info(f"Successfully connected to {device.hostname} at {device.ip}")
            config = dev.rpc.get_config(options={'format': 'text'}).text
            dev.close()
            logging.info(f"Fetched config from {device.hostname} at {device.ip}")

            config_filename = f"{device.hostname}_config.txt"
            config_filepath = os.path.join(user_folder, config_filename)
            logging.info(f"Saving config to {config_filepath}")

            with open(config_filepath, 'w') as config_file:
                config_file.write(config)
            logging.info(f"Config written successfully to {config_filepath}")

        except ConnectAuthError as e:
            logging.error(f"Connection authentication error for device {device.hostname}: {str(e)}")
            errors.append({"device": device.hostname, "message": str(e)})
        except ConnectError as e:
            logging.error(f"Connection error for device {device.hostname}: {str(e)}")
            errors.append({"device": device.hostname, "message": str(e)})
        except Exception as e:
            logging.error(f"General error for device {device.hostname}: {str(e)}")
            errors.append({"device": device.hostname, "message": str(e)})

    if errors:
        logging.info(f"Errors occurred: {errors}")
        return jsonify({"success": False, "errors": errors}), 500
    else:
        return jsonify({"success": True, "message": "All configurations saved successfully"})"""

@app.route('/save_all_device_configs', methods=['POST'])
@login_required
def save_all_device_configs():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Pls login again', 'error')
        return jsonify({'success': False, 'error': 'Please login again'}), 401

    devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
    errors = []
    user_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], str(current_user.id))
    os.makedirs(user_folder, exist_ok=True)

    total_devices = len(devices)
    for index, device in enumerate(devices):
        try:
            logging.info(f"Connecting to device {device.hostname} at {device.ip}")
            dev = Device(host=device.ip, user=device.username, passwd=device.password, port=22)
            dev.open()
            logging.info(f"Successfully connected to {device.hostname} at {device.ip}")
            config = dev.rpc.get_config(options={'format': 'text'}).text
            dev.close()
            logging.info(f"Fetched config from {device.hostname} at {device.ip}")

            config_filename = f"{device.hostname}_config.txt"
            config_filepath = os.path.join(user_folder, config_filename)
            logging.info(f"Saving config to {config_filepath}")

            with open(config_filepath, 'w') as config_file:
                config_file.write(config)
            logging.info(f"Config written successfully to {config_filepath}")

            # Emit progress update
            progress = int(((index + 1) / total_devices) * 100)
            socketio.emit('save_progress', {'device': device.hostname, 'progress': progress, 'stage': 'Completed'})

        except ConnectAuthError as e:
            logging.error(f"Connection authentication error for device {device.hostname}: {str(e)}")
            errors.append({"device": device.hostname, "message": str(e)})
            socketio.emit('save_progress', {'device': device.hostname, 'progress': 0, 'stage': 'Error', 'error': str(e)})
        except ConnectError as e:
            logging.error(f"Connection error for device {device.hostname}: {str(e)}")
            errors.append({"device": device.hostname, "message": str(e)})
            socketio.emit('save_progress', {'device': device.hostname, 'progress': 0, 'stage': 'Error', 'error': str(e)})
        except Exception as e:
            logging.error(f"General error for device {device.hostname}: {str(e)}")
            errors.append({"device": device.hostname, "message": str(e)})
            socketio.emit('save_progress', {'device': device.hostname, 'progress': 0, 'stage': 'Error', 'error': str(e)})

    if errors:
        logging.info(f"Errors occurred: {errors}")
        return jsonify({"success": False, "errors": errors}), 500
    else:
        return jsonify({"success": True, "message": "All configurations saved successfully"})



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

        try:
            cu.unlock()
        except UnlockError as unlock_error:
            logging.warning(f"UnlockError: {str(unlock_error)}. Proceeding to lock the configuration.")

        cu.lock()
        logging.info("Loading configuration...")
        emit_progress(router_ip, 50, 'Loading configuration')

        if isinstance(config_lines, str):
            config_lines = config_lines.split('\n')
        elif not isinstance(config_lines, list):
            raise ValueError("config_lines should be a list of strings")
        clean_config_lines = [line for line in config_lines if not line.startswith("##")]
        config_to_load = "\n".join(clean_config_lines)
        logging.info(f"Configuration to load: {config_to_load}")
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


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        user_folder, log_folder = create_user_folders(username)
        flash('Signup successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            user_folder, log_folder = create_user_folders(username)
            current_app.config['UPLOAD_FOLDER'] = user_folder
            current_app.config['LOG_FOLDER'] = log_folder
            setup_user_logging(username)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        flash('Login failed. Check your username and/or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/api/devices', methods=['GET'])
@login_required
def get_devices():
    devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
    devices_data = [{'id': device.id, 'hostname': device.hostname, 'ip': device.ip, 'username': device.username, 'password': device.password} for device in devices]
    return jsonify(devices_data)


@app.route('/trigger_events', methods=['GET', 'POST'])
@login_required
def trigger_events():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Pls login again', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            description = data.get('description')
            iteration = data.get('iteration')
            device_name = data.get('device_name')
            command = data.get('command')
            prediction_text = 'success'  # This should be replaced with actual prediction logic

            new_event = TriggerEvent(
                description=description,
                iteration=iteration,
                device_name=device_name,
                user_id=current_user.id,
                command=command
            )
            db.session.add(new_event)
            db.session.commit()

            return jsonify({"success": True, "prediction": prediction_text})
        else:
            return jsonify({"success": False, "message": "Invalid request"}), 400

    #devices = get_router_details_from_csv(os.path.join(current_app.config['UPLOAD_FOLDER'], 'device.csv'))
    devices = get_router_details_from_db()
    events = TriggerEvent.query.filter_by(user_id=current_user.id).all()
    return render_template('trigger_events.html', events=events, devices=devices)

@app.route('/delete_event/<int:event_id>', methods=['POST'])
@login_required
def delete_event(event_id):
    event = TriggerEvent.query.get(event_id)
    if event:
        db.session.delete(event)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Event deleted successfully'})
    return jsonify({'success': False, 'message': 'Event not found'}), 404

"""@app.route('/save_event', methods=['POST'])
@login_required
def save_event():
    data = request.json
    description = data.get('description')
    iteration = data.get('iteration')
    device_name = data.get('device_name')
    command = data.get('command')
    if not all([description, iteration, device_name, command]):
        return jsonify({'error': 'Missing data'}), 400
    new_event = TriggerEvent(
        description=description,
        iteration=iteration,
        device_name=device_name,
        command=command,
        user_id=current_user.id
    )
    db.session.add(new_event)
    db.session.commit()
    return jsonify({'success': True}), 200"""




@app.route('/edit_event/<int:event_id>', methods=['POST'])
@login_required
def edit_event(event_id):
    event = TriggerEvent.query.get(event_id)
    if not event:
        return jsonify({'success': False, 'message': 'Event not found'}), 404
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
    event.description = data.get('description', event.description)
    event.iteration = data.get('iteration', event.iteration)
    event.device_name = data.get('device_name', event.device_name)
    event.command = data.get('command', event.command)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Event updated successfully'})

@app.route('/view_events', methods=['GET'])
@login_required
def view_events():
    events = TriggerEvent.query.filter_by(user_id=current_user.id).all()
    return render_template('view_events.html', events=events)

@app.route('/edit_viewevent/<int:event_id>', methods=['GET', 'POST'])
@login_required
def edit_viewevent(event_id):
    event = TriggerEvent.query.get(event_id)
    if not event:
        flash('Event not found.', 'error')
        return redirect(url_for('view_events'))
    if request.method == 'POST':
        event.description = request.form['description']
        event.iteration = request.form['iteration']
        event.device_name = request.form['device_name']
        event.command = request.form['command']
        db.session.commit()
        flash('Event updated successfully.', 'success')
        return redirect(url_for('view_events'))

    #devices = get_router_details_from_csv(os.path.join(current_app.config['UPLOAD_FOLDER'], 'device.csv'))
    devices = get_router_details_from_db()
    return render_template('edit_event.html', event=event, devices=devices)

@app.route('/delete_events', methods=['POST'])
@login_required
def delete_events():
    data = request.json
    event_ids = data.get('event_ids', [])

    if not event_ids:
        return jsonify({'success': False, 'message': 'No event IDs provided'}), 400

    for event_id in event_ids:
        event = TriggerEvent.query.get(event_id)
        if event:
            db.session.delete(event)

    db.session.commit()
    return jsonify({'success': True, 'message': 'Events deleted successfully'})



@app.route('/restore_device_config/<int:device_id>', methods=['POST'])
@login_required
def restore_device_config_view(device_id):
    if 'UPLOAD_FOLDER' not in current_app.config:
        return jsonify(success=False, error='Please login again'), 401
    device = db.session.get(DeviceInfo, device_id)
    if not device:
        return jsonify(success=False, error='Device not found'), 404
    user_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], str(current_user.id))
    config_filename = f"{device.hostname}_config.txt"
    config_filepath = os.path.join(user_folder, config_filename)
    print(config_filepath)
    if not os.path.exists(config_filepath):
        return jsonify(success=False, error='Configuration file not found'), 404
    try:
        with open(config_filepath, 'r') as config_file:
            config_lines = config_file.readlines()
            clean_config_lines = [line for line in config_lines if not line.startswith("##")]
            config_format = 'set' if any(line.startswith('set ') for line in clean_config_lines) else 'text'
        result = transfer_file_to_router(clean_config_lines, device.ip, device.username, device.password, device.hostname, config_format)
        if "successfully" in result:
            return jsonify(success=True)
        else:
            return jsonify(success=False, error=result)
    except Exception as e:
        return jsonify(success=False, error=str(e)), 500



"""@app.route('/restore_all_device_configs', methods=['POST'])
@login_required
def restore_all_device_configs():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Please login again', 'error')
        return jsonify({'success': False, 'error': 'Please login again'}), 401

    devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
    errors = []
    user_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], str(current_user.id))

    if not os.path.exists(user_folder):
        logging.info(f"Error: No configurations found to restore {user_folder}")
        return jsonify({"success": False, "error": "No configurations found to restore"}), 400

    for device in devices:
        config_filename = f"{device.hostname}_config.txt"
        config_filepath = os.path.join(user_folder, config_filename)
        if not os.path.exists(config_filepath):
            errors.append({"device": device.hostname, "message": "Configuration file not found"})
            socketio.emit('progress', {'ip': device.ip, 'progress': 0, 'stage': 'Error', 'error': 'Configuration file not found'})
            continue

        try:
            with open(config_filepath, 'r') as config_file:
                config_lines = config_file.readlines()
                clean_config_lines = [line for line in config_lines if not line.startswith("##")]
                config_format = 'set' if any(line.startswith('set ') for line in clean_config_lines) else 'text'
                transfer_status = transfer_file_to_router(clean_config_lines, device.ip, device.username, device.password, device.hostname, config_format)
                if "successfully" not in transfer_status:
                    errors.append({"device": device.hostname, "message": transfer_status})
                    socketio.emit('progress', {'ip': device.ip, 'progress': 0, 'stage': 'Error', 'error': transfer_status})
                else:
                    socketio.emit('progress', {'ip': device.ip, 'progress': 100, 'stage': 'Completed'})
        except Exception as e:
            errors.append({"device": device.hostname, "message": str(e)})
            socketio.emit('progress', {'ip': device.ip, 'progress': 0, 'stage': 'Error', 'error': str(e)})

    if errors:
        logging.info(f"Error: {errors}")
        return jsonify({"success": False, "errors": errors}), 500
    else:
        return jsonify({"success": True, "message": "All configurations restored successfully"})
"""

"""@app.route('/restore_all_device_configs', methods=['POST'])
@login_required
def restore_all_device_configs():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Please login again', 'error')
        return jsonify({'success': False, 'error': 'Please login again'}), 401

    devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
    errors = []
    user_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], str(current_user.id))

    if not os.path.exists(user_folder):
        logging.info(f"Error: No configurations found to restore {user_folder}")
        return jsonify({"success": False, "error": "No configurations found to restore"}), 400

    total_devices = len(devices)
    restored_devices = 0

    for device in devices:
        config_filename = f"{device.hostname}_config.txt"
        config_filepath = os.path.join(user_folder, config_filename)
        if not os.path.exists(config_filepath):
            errors.append({"device": device.hostname, "message": "Configuration file not found"})
            socketio.emit('progress', {'ip': device.ip, 'progress': 0, 'stage': 'Error', 'error': 'Configuration file not found'})
            continue

        try:
            with open(config_filepath, 'r') as config_file:
                config_lines = config_file.readlines()
                clean_config_lines = [line for line in config_lines if not line.startswith("##")]
                config_format = 'set' if any(line.startswith('set ') for line in clean_config_lines) else 'text'
                transfer_status = transfer_file_to_router(clean_config_lines, device.ip, device.username, device.password, device.hostname, config_format)
                if "successfully" not in transfer_status:
                    errors.append({"device": device.hostname, "message": transfer_status})
                    socketio.emit('progress', {'ip': device.ip, 'progress': 0, 'stage': 'Error', 'error': transfer_status})
                else:
                    restored_devices += 1
                    overall_progress = int((restored_devices / total_devices) * 100)
                    socketio.emit('overall_progress', {'progress': overall_progress})
                    socketio.emit('progress', {'ip': device.ip, 'progress': 100, 'stage': 'Completed'})
        except Exception as e:
            errors.append({"device": device.hostname, "message": str(e)})
            socketio.emit('progress', {'ip': device.ip, 'progress': 0, 'stage': 'Error', 'error': str(e)})

    if errors:
        logging.info(f"Error: {errors}")
        return jsonify({"success": False, "errors": errors}), 500
    else:
        return jsonify({"success": True, "message": "All configurations restored successfully"})
"""

@app.route('/restore_all_device_configs', methods=['POST'])
@login_required
def restore_all_device_configs():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Please login again', 'error')
        return jsonify({'success': False, 'error': 'Please login again'}), 401

    devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
    errors = []
    user_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], str(current_user.id))

    if not os.path.exists(user_folder):
        logging.info(f"Error: No configurations found to restore {user_folder}")
        return jsonify({"success": False, "error": "No configurations found to restore"}), 400

    total_devices = len(devices)
    completed_devices = 0

    for device in devices:
        config_filename = f"{device.hostname}_config.txt"
        config_filepath = os.path.join(user_folder, config_filename)
        if not os.path.exists(config_filepath):
            errors.append({"device": device.hostname, "message": "Configuration file not found"})
            socketio.emit('progress', {'ip': device.ip, 'progress': 0, 'stage': 'Error', 'error': 'Configuration file not found'})
            continue

        try:
            with open(config_filepath, 'r') as config_file:
                config_lines = config_file.readlines()
                clean_config_lines = [line for line in config_lines if not line.startswith("##")]
                config_format = 'set' if any(line.startswith('set ') for line in clean_config_lines) else 'text'
                transfer_status = transfer_file_to_router(clean_config_lines, device.ip, device.username, device.password, device.hostname, config_format)
                if "successfully" not in transfer_status:
                    errors.append({"device": device.hostname, "message": transfer_status})
                    socketio.emit('progress', {'ip': device.ip, 'progress': 0, 'stage': 'Error', 'error': transfer_status})
                else:
                    completed_devices += 1
                    overall_progress = (completed_devices / total_devices) * 100
                    socketio.emit('progress', {'ip': device.ip, 'progress': 100, 'stage': 'Completed'})
                    socketio.emit('overall_progress', {'progress': overall_progress})
        except Exception as e:
            errors.append({"device": device.hostname, "message": str(e)})
            socketio.emit('progress', {'ip': device.ip, 'progress': 0, 'stage': 'Error', 'error': str(e)})

    if errors:
        logging.info(f"Error: {errors}")
        return jsonify({"success": False, "errors": errors}), 500
    else:
        return jsonify({"success": True, "message": "All configurations restored successfully"})


@app.route('/api/events', methods=['GET'])
@login_required
def api_events():
    events = TriggerEvent.query.filter_by(user_id=current_user.id).all()
    events_data = [{
        'id': event.id,
        'description': event.description,
        'iteration': event.iteration,
        'device_name': event.device_name,
        'command': event.command
    } for event in events]
    return jsonify(events_data)

@app.route('/debug_log')
@login_required
def debug_log():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Pls login again', 'error')
        return redirect(url_for('index'))
    if 'LOG_FOLDER' not in current_app.config:
        flash('Pls login again', 'error')
        return redirect(url_for('index'))
    log_file_path = os.path.join(current_app.config['LOG_FOLDER'], 'debug.log')
    try:
        with open(log_file_path, 'r') as file:
            log_content = file.read()
    except FileNotFoundError:
        log_content = 'Log file not found.'

    return render_template('debug_log.html', log_content=log_content)

@app.route('/download_log')
@login_required
def download_log():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Pls login again', 'error')
        return redirect(url_for('index'))
    if 'LOG_FOLDER' not in current_app.config:
        flash('Pls login again', 'error')
        return redirect(url_for('index'))
    log_file_path = os.path.join(current_app.config['LOG_FOLDER'], 'debug.log')
    return send_file(log_file_path, as_attachment=True, download_name='debug.log')


def simplified_neighbors_dict(neighbors_dict):
    """Remove domain suffix from the keys and values"""
    simplified_neighbors_dict = {}
    for key, values in neighbors_dict.items():
        simplified_key = key.split('.')[0]
        simplified_values = [(value[0].split('.')[0], value[1], value[2]) for value in values]
        simplified_neighbors_dict[simplified_key] = simplified_values
    return simplified_neighbors_dict


## Discover topology useing lldp and  Configure network ##
@app.route('/show_generated_config', methods=['POST'])
@login_required
def show_generated_config_route():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Pls login again', 'error')
        return redirect(url_for('index'))
    config_method = request.form.get('config_method')
    commands = defaultdict(list)
    local_as_mapping = {}
    neighbors_dict = defaultdict(list)
    as_counter = 65000
    success_hosts = []
    failed_hosts = set()
    logging.info(f"Configuration method selected: {config_method}")
    logging.info(f"Current user ID: {current_user.id}")
    if config_method == 'csv':
        pass  # Existing code for CSV processing remains unchanged
    elif config_method == 'lldp':
        devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
        logging.info(f"Devices found: {devices}")
        if not devices:
            logging.info(f"No devices found for user {current_user.id}")
            flash('No devices found for the current user.', 'error')
            return redirect(url_for('index'))
        for device in devices:
            if device.hostname not in local_as_mapping:
                local_as_mapping[device.hostname] = as_counter
                as_counter += 1
                commands[device.hostname].extend(generate_common_config())
        for device in devices:
            hostname = device.hostname
            router_ip = device.ip
            router_user = device.username
            router_password = device.password
            logging.info(f"Attempting to connect to device: {hostname} at IP: {router_ip}")
            try:
                with Device(host=router_ip, user=router_user, passwd=router_password, port=22) as dev:
                    logging.info(f"Successfully connected to {hostname}")
                    neighbors = dev.rpc.get_lldp_neighbors_information()
                    logging.info(
                        f"LLDP neighbors information for {hostname}: {etree.tostring(neighbors, pretty_print=True).decode('utf-8')}")
                    for neighbor in neighbors.findall('.//lldp-neighbor-information'):
                        interface = neighbor.find('lldp-local-port-id').text.strip()
                        remote_system_name = neighbor.find('lldp-remote-system-name').text.strip()
                        remote_port_desc = neighbor.find('lldp-remote-port-description').text.strip()

                        if remote_system_name and remote_port_desc:
                            logging.info(
                                f"Neighbor found - Interface: {interface}, Remote System Name: {remote_system_name}, Remote Port Desc: {remote_port_desc}")
                            neighbors_dict[hostname].append((remote_system_name, interface, remote_port_desc))
            except Exception as e:
                logging.error(f"Failed to fetch LLDP neighbors for {hostname}: {e}")
                failed_hosts.add((hostname, f"Failed to fetch LLDP neighbors: {e}"))
        if not neighbors_dict:
            logging.info("No LLDP neighbors found for any device.")
            return render_template('upload_result.html', success_hosts=success_hosts, failed_hosts=list(failed_hosts), commands=commands)
        logging.info(f"neighbors_dict: {neighbors_dict}")
        logging.info(f"Commands: {commands}")
        logging.info(f"Local AS Mapping: {local_as_mapping}")
        """remove domain suffix from hostname"""
        trim_domain_neighbors = simplified_neighbors_dict(neighbors_dict)
        """Prepare the connections list from neighbors_dict"""
        connections = []
        for key, values in trim_domain_neighbors.items():
            for value in values:
                connection = {
                    key: value[1],
                    value[0]: value[2]
                }
                connections.append(connection)
        logging.info(f"LLDP Neighbors Connections: {connections}")
        generate_config(commands, connections, local_as_mapping)
    session['generated_config'] = commands
    return render_template('upload_result.html', success_hosts=success_hosts, failed_hosts=list(failed_hosts),
                           commands=commands)

"""@app.route('/show_csvgenerated_config', methods=['GET', 'POST'])
@login_required
def show_csvgenerated_config():
    if request.method == 'POST':
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash('Pls login again', 'error')
            return redirect(url_for('index'))
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        if file.filename == '':
            return 'No selected file'
        if file:
            config_file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file.filename)
            file.save(config_file_path)
            commands = defaultdict(list)
            local_as_mapping = {}
            peer_mapping = defaultdict(list)
            delete_group = request.form.get("delete_group")
            with open(config_file_path, mode='r') as csv_file:
                csv_reader = csv.DictReader(csv_file)

                as_counter = 65000
                for row in csv_reader:
                    hostname = row['hostname']
                    interface = row['interface']
                    ip_addr = row['ip_addr']
                    underlay_protocol = row['underlay_protocol']
                    logging.info(f"Parsed values - hostname: {hostname}, interface: {interface}, ip_addr: {ip_addr}, underlay_protocol: {underlay_protocol}")
                    if hostname not in local_as_mapping:
                        local_as_mapping[hostname] = as_counter
                        as_counter += 1
                        commands[hostname].extend(generate_common_config())
                    commands[hostname].extend(generate_interface_config(interface, ip_addr))
                    peer_ip = ip_addr.split('/')[0]
                    if underlay_protocol.lower() == 'bgp':
                        peer_mapping[ip_addr.rsplit('.', 1)[0]].append((hostname, peer_ip))

            for subnet, peers in peer_mapping.items():
                export_policy_added = {}
                for i, (hostname1, peer_ip1) in enumerate(peers):
                    for hostname2, peer_ip2 in peers[i + 1:]:
                        if hostname1 != hostname2:
                            local_as1 = local_as_mapping[hostname1]
                            local_as2 = local_as_mapping[hostname2]
                            include_export_policy1 = hostname1 not in export_policy_added
                            include_export_policy2 = hostname2 not in export_policy_added
                            delete_group1 = not any("delete protocols bgp group underlay" in cmd for cmd in commands[hostname1])
                            delete_group2 = not any("delete protocols bgp group underlay" in cmd for cmd in commands[hostname2])
                            commands[hostname1].extend(
                                generate_bgp_config(peer_ip1, peer_ip2, local_as1, local_as2, include_export_policy1, delete_group1))
                            commands[hostname2].extend(
                                generate_bgp_config(peer_ip2, peer_ip1, local_as2, local_as1, include_export_policy2, delete_group2))
                            export_policy_added[hostname1] = True
                            export_policy_added[hostname2] = True
            return render_template('upload_result.html', commands=commands)
"""


@app.route('/show_csvgenerated_config', methods=['GET', 'POST'])
@login_required
def show_csvgenerated_config():
    if request.method == 'POST':
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash('Pls login again', 'error')
            return redirect(url_for('index'))
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        if file.filename == '':
            return 'No selected file'
        if file:
            config_file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file.filename)
            file.save(config_file_path)
            commands = defaultdict(list)
            local_as_mapping = {}
            peer_mapping = defaultdict(list)
            delete_group = request.form.get("delete_group")
            with open(config_file_path, mode='r') as csv_file:
                csv_reader = csv.DictReader(csv_file)
                as_counter = 65000
                for row in csv_reader:
                    hostname = row['hostname']
                    interface = row['interface']
                    ip_addr = row['ip_addr']
                    underlay_protocol = row['underlay_protocol']
                    logging.info(f"Parsed values - hostname: {hostname}, interface: {interface}, ip_addr: {ip_addr}, underlay_protocol: {underlay_protocol}")
                    if hostname not in local_as_mapping:
                        local_as_mapping[hostname] = as_counter
                        as_counter += 1
                        commands[hostname].extend(generate_common_config())
                    commands[hostname].extend(generate_interface_config(interface, ip_addr))
                    peer_ip = ip_addr.split('/')[0]
                    if underlay_protocol.lower() == 'bgp':
                        peer_mapping[ip_addr.rsplit('.', 1)[0]].append((hostname, peer_ip))

            for subnet, peers in peer_mapping.items():
                export_policy_added = {}
                for i, (hostname1, peer_ip1) in enumerate(peers):
                    for hostname2, peer_ip2 in peers[i + 1:]:
                        if hostname1 != hostname2:
                            local_as1 = local_as_mapping[hostname1]
                            local_as2 = local_as_mapping[hostname2]
                            include_export_policy1 = hostname1 not in export_policy_added
                            include_export_policy2 = hostname2 not in export_policy_added
                            delete_group1 = not any("delete protocols bgp group underlay" in cmd for cmd in commands[hostname1])
                            delete_group2 = not any("delete protocols bgp group underlay" in cmd for cmd in commands[hostname2])
                            commands[hostname1].extend(
                                generate_bgp_config(peer_ip1, peer_ip2, local_as1, local_as2, include_export_policy1, delete_group1))
                            commands[hostname2].extend(
                                generate_bgp_config(peer_ip2, peer_ip1, local_as2, local_as1, include_export_policy2, delete_group2))
                            export_policy_added[hostname1] = True
                            export_policy_added[hostname2] = True

            # Save each device's configuration to a file
            user_folder = os.path.join(current_app.config['UPLOAD_FOLDER'])
            os.makedirs(user_folder, exist_ok=True)
            for hostname, cmds in commands.items():
                config_filename = f"{hostname}_config.txt"
                config_filepath = os.path.join(user_folder, config_filename)
                with open(config_filepath, 'w') as config_file:
                    config_file.write("\n".join(cmds))

            devices = get_router_details_from_db()
            download_link = True
            return render_template('upload_result.html', commands=commands, devices=devices, download_link=download_link)

def generate_common_config():
    return [
        "set policy-options policy-statement export_lo0 term 1 from interface lo0",
        "set policy-options policy-statement export_lo0 term 1 then accept",
        "set protocols lldp interface all"
    ]

def generate_interface_config(interface, ip_address):
    return [
        f"delete interfaces {interface} unit 0 family inet",
        f"set interfaces {interface} unit 0 family inet address {ip_address}/30"
    ]

def generate_bgp_config(local_ip, neighbor_ip, local_as, remote_as, include_export_policy=False, delete_group=False):
    commands = []
    if delete_group:
        if request.form.get("delete_group") is not None:
            commands.append("delete protocols bgp group underlay")
    commands.extend([
        "set protocols bgp group underlay type external",
        f"set protocols bgp group underlay neighbor {neighbor_ip} peer-as {remote_as}",
        f"set protocols bgp group underlay neighbor {neighbor_ip} local-address {local_ip}",
        f"set protocols bgp group underlay local-as {local_as}",
        f"set protocols bgp group underlay neighbor {neighbor_ip} family inet unicast"
    ])
    if include_export_policy:
        commands.append("set protocols bgp group underlay export export_lo0")
    logging.info(f"** generate_bgp_config: Commands: {commands}")
    return commands


def generate_config(commands, connections, local_as_mapping):
    ip_assignments = {}
    subnet_counter = 1
    def get_ip(subnet_counter, host_id):
        return f"192.168.{subnet_counter}.{host_id}"
    def get_subnet(ip_address):
        return ipaddress.ip_network(ip_address + '/30', strict=False)
    configured_interfaces = {}
    skip_interfaces = {'re0:mgmt-0', 'em0', 'fxp0'}
    skip_device_patterns = ['mgmt', 'management', 'hypercloud']
    for connection in connections:
        subnet = subnet_counter
        subnet_counter += 1
        host_id = 1
        neighbor_ip_mapping = {}
        if isinstance(connection, dict):
            for device, interface in connection.items():
                if any(pattern in device.lower() for pattern in skip_device_patterns) or interface in skip_interfaces:
                    continue
                if device not in ip_assignments:
                    ip_assignments[device] = []
                if device not in configured_interfaces:
                    configured_interfaces[device] = set()

                if interface not in configured_interfaces[device]:
                    ip_address = get_ip(subnet, host_id)
                    ip_assignments[device].append((interface, ip_address))
                    configured_interfaces[device].add(interface)
                    neighbor_ip_mapping[interface] = ip_address
                    host_id += 1

            for device, interface in connection.items():
                if any(pattern in device.lower() for pattern in skip_device_patterns) or interface in skip_interfaces or interface not in neighbor_ip_mapping:
                    continue
                local_subnet = get_subnet(neighbor_ip_mapping[interface])
                for remote_device, remote_interface in connection.items():
                    if remote_device != device and remote_interface in neighbor_ip_mapping:
                        remote_subnet = get_subnet(neighbor_ip_mapping[remote_interface])
                        if local_subnet == remote_subnet:
                            local_as = local_as_mapping.get(device)
                            remote_as = local_as_mapping.get(remote_device)
                            if local_as is not None and remote_as is not None:
                                neighbor_ip = neighbor_ip_mapping[remote_interface]
                                local_ip = neighbor_ip_mapping[interface]
                                delete_group = not any("delete protocols bgp group underlay" in cmd for cmd in commands[device])
                                bgp_commands = generate_bgp_config(local_ip, neighbor_ip, local_as, remote_as, True, delete_group)
                                if device not in commands:
                                    commands[device] = []
                                commands[device].extend(bgp_commands)

    for device, interfaces in ip_assignments.items():
        if any(pattern in device.lower() for pattern in skip_device_patterns):
            continue
        if device not in commands:
            commands[device] = []
        if "set policy-options policy-statement export_lo0 term 1 from interface lo0" not in commands[device]:
            commands[device].extend(generate_common_config())
        for interface, ip_address in interfaces:
            commands[device].extend(generate_interface_config(interface, ip_address))


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash('Pls login again', 'error')
            return redirect(url_for('index'))
        config_method = request.form.get('config_method')
        button_clicked = request.form.get('button_clicked')
        username = request.form['username']
        password = request.form['password']
        generated_config = session.get('generated_config')

        if config_method == 'csv':
            # Process CSV and store generated configuration in the session
            file = request.files.get('file')
            if file and file.filename != '':
                config_file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file.filename)
                file.save(config_file_path)
                commands = defaultdict(list)
                local_as_mapping = {}
                peer_mapping = defaultdict(list)

                with open(config_file_path, mode='r') as csv_file:
                    csv_reader = csv.DictReader(csv_file)
                    as_counter = 65000
                    for row in csv_reader:
                        hostname = row['hostname']
                        interface = row['interface']
                        ip_addr = row['ip_addr']
                        underlay_protocol = row['underlay_protocol']

                        logging.info(
                            f"Parsed values - hostname: {hostname}, interface: {interface}, ip_addr: {ip_addr}, underlay_protocol: {underlay_protocol}")

                        if hostname not in local_as_mapping:
                            local_as_mapping[hostname] = as_counter
                            as_counter += 1
                            commands[hostname].extend(generate_common_config())

                        commands[hostname].extend(generate_interface_config(interface, ip_addr))
                        peer_ip = ip_addr.split('/')[0]

                        if underlay_protocol.lower() == 'bgp':
                            peer_mapping[ip_addr.rsplit('.', 1)[0]].append((hostname, peer_ip))

                for subnet, peers in peer_mapping.items():
                    export_policy_added = {}
                    for i, (hostname1, peer_ip1) in enumerate(peers):
                        for hostname2, peer_ip2 in peers[i + 1:]:
                            if hostname1 != hostname2:
                                local_as1 = local_as_mapping[hostname1]
                                local_as2 = local_as_mapping[hostname2]
                                include_export_policy1 = hostname1 not in export_policy_added
                                include_export_policy2 = hostname2 not in export_policy_added
                                commands[hostname1].extend(
                                    generate_bgp_config(peer_ip1, peer_ip2, local_as1, local_as2,
                                                        include_export_policy1))
                                commands[hostname2].extend(
                                    generate_bgp_config(peer_ip2, peer_ip1, local_as2, local_as1,
                                                        include_export_policy2))
                                export_policy_added[hostname1] = True
                                export_policy_added[hostname2] = True

                session['generated_config'] = commands

        # Ensure generated_config is available in session
        generated_config = session.get('generated_config')
        if generated_config is None:
            flash('No generated configuration found. Please generate the configuration first.', 'error')
            return redirect(url_for('index'))
        success_hosts = []
        failed_hosts = []
        total_rows = len(generated_config)
        devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
        logging.info(f"Devices in Database: {devices}")
        logging.info("Starting to transfer configuration to devices...")
        for i, (host, config_lines) in enumerate(generated_config.items()):
            router_user = username
            router_password = password
            device_name = None
            if not router_user or not router_password:
                for device in devices:
                    if device.hostname == host:
                        router_user = device.username
                        router_password = device.password
                        device_name = device.hostname
                        break

            try:
                logging.info(f"Transferring configuration to {host}")
                config_format="set"
                transfer_status = transfer_file_to_router(config_lines, host, router_user, router_password, device_name,config_format)
                if "successfully" in transfer_status:
                    success_hosts.append(host)
                else:
                    failed_hosts.append((host, transfer_status))
                progress = (i + 1) / total_rows * 100
                socketio.emit('progress', {'progress': progress, 'hostname': host, 'status': transfer_status,
                                           'command': "\n".join(config_lines)})
                time.sleep(0.1)
            except Exception as e:
                failed_hosts.append((host, str(e)))
                logging.error(f"Error transferring config to {host}: {str(e)}")
                continue

        logging.info("Configuration transfer complete.")
        return render_template('upload_result.html', success_hosts=success_hosts, failed_hosts=failed_hosts,
                               commands=generated_config)
    return render_template('upload.html')


@app.route('/upload_config', methods=['GET', 'POST'])
@login_required
def upload_config():
    if request.method == 'POST':
        config_file = request.files.get('file')
        config_text = request.form.get('config_textarea')
        router_ips = request.form['router_ips'].split(',')
        router_user = request.form['router_user']
        router_password = request.form['router_password']

        def emit_progress(router_ip, progress, error=None):
            socketio.emit('progress', {'ip': router_ip, 'progress': progress, 'error': error}, namespace='/')

        def handle_device(router_ip, router_user, router_password, config_to_load, config_format, results):
            try:
                emit_progress(router_ip, 0)
                dev = Device(host=router_ip, user=router_user, passwd=router_password, port=22)
                dev.open()
                emit_progress(router_ip, 25)
                cu = Config(dev)
                cu.lock()
                emit_progress(router_ip, 50)
                cu.load(config_to_load, format=config_format, ignore_warning=True)
                emit_progress(router_ip, 75)
                cu.commit()
                cu.unlock()
                dev.close()
                emit_progress(router_ip, 100)
                results[router_ip] = {'success': True, 'message': 'Configuration loaded successfully'}
            except (ConnectAuthError, ConnectError, ConfigLoadError, CommitError) as e:
                logging.error(f"Error loading configuration on {router_ip}: {str(e)}")
                emit_progress(router_ip, 0, error=str(e))
                results[router_ip] = {'success': False, 'message': str(e)}
            except Exception as e:
                logging.error(f"Unexpected error on {router_ip}: {str(e)}")
                emit_progress(router_ip, 0, error=str(e))
                results[router_ip] = {'success': False, 'message': str(e)}

        if config_file:
            config_file_path = os.path.join(app.config['UPLOAD_FOLDER'], config_file.filename)
            config_file.save(config_file_path)
            with open(config_file_path, 'r') as file:
                config_lines = file.readlines()
                logging.info(config_lines)
        elif config_text:
            config_lines = config_text.splitlines()
            logging.info(config_lines)
        else:
            return 'No configuration provided', 400

        # Determine the format to use
        if any(line.startswith(("set", "delete")) for line in config_lines):
            config_format = 'set'
        else:
            config_format = 'text'

        # Filter out lines starting with ## and empty lines
        clean_config_lines = [line for line in config_lines if line.strip() and not line.startswith("##")]
        config_to_load = "\n".join(clean_config_lines)
        logging.info(f"Configuration to load: {config_to_load}")

        results = {}
        threads = []

        for router_ip in router_ips:
            thread = threading.Thread(target=handle_device, args=(router_ip.strip(), router_user, router_password, config_to_load, config_format, results))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        success = all(result['success'] for result in results.values())
        return jsonify(success=success, results=results)
    return render_template('upload_config.html')



@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'GET':
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash('Pls login again', 'error')
            return render_template('generate_l2_config.html')
        if 'LOG_FOLDER' not in current_app.config:
            flash('Pls login again', 'error')
            return render_template('generate_l2_config.html')
    if request.method == 'POST':
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash('Pls login again', 'error')
            return redirect(url_for('index'))
        if request.method == 'POST':
            num_vlans_per_interface = int(request.form['num_vlans_per_interface'])
            base_ip_parts = list(map(int, request.form['base_ip_parts'].split('.')))
            interface_prefixes = request.form['interface_prefixes'].split()
            last_octet = int(request.form['last_octet'])
            base_vlan_id = int(request.form['base_vlan_id'])
            filename = request.form.get('filename', 'config.txt')
            access = 'access' in request.form
            trunk = 'trunk' in request.form
            native_vlanid = 'native_vlanid' in request.form
            native_vlanid_value = request.form.get('native_vlanid_value', '')

            all_config_lines = []
            current_vlan_id = base_vlan_id
            vlan_ids = [current_vlan_id + i for i in range(num_vlans_per_interface)]
            current_vlan_id += num_vlans_per_interface
            config_lines = generate_vlan_config(interface_prefixes, vlan_ids, base_ip_parts, last_octet, access, trunk,
                                                native_vlanid, native_vlanid_value)
            all_config_lines.extend(config_lines)
            config_text = "\n".join(all_config_lines)
            config_file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            with open(config_file_path, "w") as config_file:
                config_file.write(config_text)
            download_link = True
            devices = get_router_details_from_db()
            return render_template('result_generate_l2_config.html', config_lines=all_config_lines,
                                   download_link=download_link, filename=filename, devices=devices)

        elif 'bgp_local_as' in request.form:
            initial_local_as = int(request.form['bgp_local_as'])
            initial_peer_as = int(request.form['bgp_as_number'])
            bgp_base_neighbor = request.form['bgp_base_neighbor']
            bgp_network = request.form['bgp_network']
            neighbor_count = int(request.form['neighbor_count'])
            as_type = request.form['as_type']
            bgp_filename = request.form['bgp_filename']
            config_lines = generate_bgp_scale_config(initial_local_as, initial_peer_as, bgp_base_neighbor, bgp_network,
                                                     neighbor_count, as_type)
            config_text = "\n".join(config_lines)
            config_file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], bgp_filename)
            with open(config_file_path, "w") as config_file:
                config_file.write(config_text)
            download_link = True
            #devices = get_router_details_from_csv(os.path.join(current_app.config['UPLOAD_FOLDER'], 'device.csv'))
            devices = get_router_details_from_db()
            return render_template('result_generate_l2_config.html', config_lines=config_lines,
                                   download_link=download_link, filename=bgp_filename, devices=devices)
        elif 'num_spines' in request.form:
            num_spines = int(request.form['num_spines'])
            num_leafs = int(request.form['num_leafs'])
            spine_ips = [request.form.get(f'spine_ip_{i}', None) for i in range(num_spines)]
            leaf_ips = [request.form.get(f'leaf_ip_{i}', None) for i in range(num_leafs)]
            base_ip_parts = list(map(int, request.form['base_ip_parts'].split('.')))
            last_octet = int(request.form['last_octet'])
            base_vxlan_vni = int(request.form['base_vxlan_vni'])
            base_vxlan_vlan_id = int(request.form['base_vxlan_vlan_id'])
            num_vxlan_configs = int(request.form['num_vxlan_configs'])
            vxlan_filename = request.form['vxlan_filename']
            generate_overlay_config = 'generate_overlay_config' in request.form
            spine_configs, leaf_configs = generate_vxlan_config(spine_ips, leaf_ips, base_ip_parts, last_octet,
                                                                base_vxlan_vni, base_vxlan_vlan_id, num_vxlan_configs,
                                                                generate_overlay_config)
            for i, spine_config in enumerate(spine_configs):
                filename = f"spine_{i + 1}_{vxlan_filename}"
                config_file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                with open(config_file_path, "w") as config_file:
                    config_file.write("\n".join(spine_config))
            for i, leaf_config in enumerate(leaf_configs):
                filename = f"leaf_{i + 1}_{vxlan_filename}"
                config_file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                with open(config_file_path, "w") as config_file:
                    config_file.write("\n".join(leaf_config))
            download_link = True
            #devices = get_router_details_from_csv(os.path.join(current_app.config['UPLOAD_FOLDER'], 'device.csv'))
            devices = get_router_details_from_db()
            return render_template('result_generate_vxlan_config.html',
                                   spine_configs=spine_configs, leaf_configs=leaf_configs,
                                   download_link=download_link, vxlan_filename=vxlan_filename, enumerate=enumerate, devices=devices)
    return render_template('generate_l2_config.html')


def generate_bgp_scale_config(initial_local_as, initial_peer_as, bgp_base_neighbor, bgp_network, neighbor_count, as_type):
    config_lines = []
    # Add policy-options statements once
    config_lines.append(f"set policy-options policy-statement export-policy term 1 from interface lo0.0")
    config_lines.append(f"set policy-options policy-statement export-policy term 1 then accept")
    config_lines.append(f"set protocols bgp group external export export-policy")
    config_lines.append(f"set protocols bgp group external type external")
    config_lines.append(f"set protocols bgp group external family inet unicast")
    base_ip_parts = list(map(int, bgp_base_neighbor.split('.')))
    for i in range(neighbor_count):
        neighbor_ip = f"{base_ip_parts[0]}.{base_ip_parts[1]}.{base_ip_parts[2]}.{base_ip_parts[3] + i}"
        current_local_as = initial_local_as if as_type == 'global' else initial_local_as + i
        current_peer_as = initial_peer_as + i
        config_lines.append(f"set protocols bgp group external neighbor {neighbor_ip} peer-as {current_peer_as}")
        config_lines.append(f"set protocols bgp group external neighbor {neighbor_ip} local-as {current_local_as}")
    return config_lines


@app.route('/bgp', methods=['POST'])
@login_required
def bgp():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Pls login again', 'error')
        return redirect(url_for('index'))
    initial_local_as = int(request.form['bgp_local_as'])
    initial_peer_as = int(request.form['bgp_as_number'])
    bgp_base_neighbor = request.form['bgp_base_neighbor']
    bgp_network = request.form['bgp_network']
    neighbor_count = int(request.form['neighbor_count'])
    as_type = request.form['as_type']
    bgp_filename = request.form['bgp_filename']
    config_lines = generate_bgp_scale_config(initial_local_as, initial_peer_as, bgp_base_neighbor, bgp_network,
                                             neighbor_count, as_type)
    config_text = "\n".join(config_lines)
    config_file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], bgp_filename)
    with open(config_file_path, "w") as config_file:
        config_file.write(config_text)

    #devices = get_router_details_from_csv(os.path.join(current_app.config['UPLOAD_FOLDER'], 'device.csv'))
    devices = get_router_details_from_db()
    download_link = True
    return render_template('result_generate_l2_config.html', config_lines=config_lines, download_link=download_link,
                           filename=bgp_filename, devices=devices)


## Transfer config to Device ##

@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Pls login again', 'error')
        return redirect(url_for('index'))
    filename = request.form['filename']
    router_ip = request.form['router_ip']
    #router_user = request.form['router_user']
    #router_password = request.form['router_password']
    device_name = None

    devices = get_router_details_from_db()
    logging.info(devices)
    for device in devices:
        if device['ip'] == router_ip:
            router_user = device['username']
            router_password = device['password']
            device_name = device['hostname']
            break

    config_file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    logging.info(f"Transfer file to device: {router_ip} - {config_file_path}")
    try:
        with open(config_file_path, 'r') as config_file:
            config_lines = config_file.readlines()
        config_format = "set"
        transfer_status = transfer_file_to_router(config_lines, router_ip, router_user, router_password, device_name,
                                                  config_format)
        logging.info(f"Tranfer status for device {router_ip} - {transfer_status}")
        response = {
            'success': 'successfully' in transfer_status,
            'message': transfer_status
        }
    except Exception as e:
        response = {
            'success': False,
            'message': str(e)
        }
    logging.info(f"Transfer response: {response}")  # Log the response
    return jsonify(response)


"""@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Pls login again', 'error')
        return redirect(url_for('index'))
    filename = request.form['filename']
    router_ip = request.form['router_ip']
    router_user = request.form['router_user']
    router_password = request.form['router_password']
    device_name = None

    if not router_user or not router_password:
        #devices = get_router_details_from_csv(os.path.join(current_app.config['UPLOAD_FOLDER'], 'device.csv'))
        devices = get_router_details_from_db()
        for device in devices:
            if device['ip'] == router_ip:
                router_user = device['username']
                router_password = device['password']
                device_name = device['hostname']
                break

    config_file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    with open(config_file_path, 'r') as config_file:
        config_lines = config_file.readlines()
    config_format="set"
    transfer_status = transfer_file_to_router(config_lines, router_ip, router_user, router_password, device_name,config_format)

    response = {
        'success': 'successfully' in transfer_status,
        'message': transfer_status
    }
    return jsonify(response)"""

def generate_vxlan_config(spine_ips, leaf_ips, base_ip_parts, last_octet, base_vxlan_vni, base_vxlan_vlan_id,
                          num_vxlan_configs, generate_overlay_config,leaf_base_as,spine_base_as):
    spine_configs = []
    leaf_configs = []
    spine_as = spine_base_as
    leaf_as = leaf_base_as
    overlay_gateway = "overlay-gateway"
    for i, spine_ip in enumerate(spine_ips):
        spine_config = []
        spine_config.append(f"set interfaces lo0.0 family inet address {spine_ip} primary preferred")
        spine_config.append(f"set routing-options router-id {spine_ip}")
        spine_config.append(f"set routing-options autonomous-system  {spine_as + i}")
        spine_config.append(f"set protocols bgp group overlay type internal")
        spine_config.append(f"set protocols bgp group overlay local-address {spine_ip}")
        #spine_config.append(f"set protocols bgp group overlay local-as {spine_as + i}")
        spine_config.append(f"set protocols bgp group overlay family evpn signaling")
        for j, leaf_ip in enumerate(leaf_ips):
            spine_config.append(f"set protocols bgp group overlay neighbor {leaf_ip} peer-as {leaf_as + j}")
        spine_configs.append(spine_config)

    for j, leaf_ip in enumerate(leaf_ips):
        print(j, leaf_as)
        print(type(leaf_as))
        leaf_config = []
        leaf_config.append(f"set interfaces lo0.0 family inet address {leaf_ip} primary preferred")
        leaf_config.append(f"set routing-options router-id {leaf_ip}")
        leaf_config.append(f"set routing-options autonomous-system  {leaf_as + j}")
        leaf_config.append(f"set protocols bgp group overlay type internal")
        leaf_config.append(f"set protocols bgp group overlay local-address {leaf_ip}")
        leaf_config.append(f"set protocols bgp group overlay family evpn signaling")
        for i, spine_ip in enumerate(spine_ips):
            leaf_config.append(f"set protocols bgp group overlay neighbor {spine_ip}")

        if generate_overlay_config:
            for k in range(num_vxlan_configs):
                vxlan_vni = base_vxlan_vni + k
                vxlan_vlan_id = base_vxlan_vlan_id + k
                ip_address = f"{base_ip_parts[0]}.{base_ip_parts[1]}.{base_ip_parts[2]}.{last_octet}/24"
                leaf_config.append(f"set routing-instances MACVRF{vxlan_vlan_id} instance-type mac-vrf")
                leaf_config.append(f"set routing-instances MACVRF{vxlan_vlan_id} protocols evpn encapsulation vxlan")
                leaf_config.append(
                    f"set routing-instances MACVRF{vxlan_vlan_id} protocols evpn default-gateway no-gateway-community ")
                leaf_config.append(
                    f"set routing-instances MACVRF{vxlan_vlan_id} protocols evpn extended-vni-list {vxlan_vni} ")
                leaf_config.append(f"set routing-instances MACVRF{vxlan_vlan_id} protocols evpn remote-ip-host-routes")
                leaf_config.append(f"set routing-instances MACVRF{vxlan_vlan_id} vtep-source-interface lo0.0")
                leaf_config.append(f"set routing-instances MACVRF{vxlan_vlan_id} service-type vlan-aware")
                leaf_config.append(f"set routing-instances MACVRF{vxlan_vlan_id} route-distinguisher {leaf_ip}:{vxlan_vni}")
                leaf_config.append(f"set routing-instances MACVRF{vxlan_vlan_id} vrf-target target:{leaf_ip}:{vxlan_vni}")
                leaf_config.append(
                    f"set routing-instances MACVRF{vxlan_vlan_id} vlans vlan{vxlan_vlan_id} vlan-id {vxlan_vlan_id}")
                leaf_config.append(
                    f"set routing-instances MACVRF{vxlan_vlan_id} vlans vlan{vxlan_vlan_id} vxlan vni {vxlan_vni}")
                leaf_config.append(
                    f"set routing-instances MACVRF{vxlan_vlan_id} vlans vlan{vxlan_vlan_id} l3-interface irb.{vxlan_vlan_id}")
                leaf_config.append(f"set interfaces irb.{vxlan_vlan_id} family inet address {ip_address}")
                last_octet += 1
                if last_octet > 254:
                    last_octet = 1
                    if base_ip_parts[2] == 254:
                        base_ip_parts[1] += 1
                        base_ip_parts[2] = 0
                    else:
                        base_ip_parts[2] += 1

        leaf_configs.append(leaf_config)
    return spine_configs, leaf_configs

def generate_vlan_config(interface_prefixes, vlan_ids, base_ip_parts, last_octet, access, trunk, native_vlanid, native_vlanid_value):
    config_lines = []
    vlan_irb_lines = []
    interface_lines = []
    native_vlanid_configured = {interface_prefix: False for interface_prefix in interface_prefixes}

    for vlan_id in vlan_ids:
        ip_address = f"{base_ip_parts[0]}.{base_ip_parts[1]}.{base_ip_parts[2]}.{last_octet}/24"
        vlan_irb_lines.append(f"set vlans v{vlan_id} vlan-id {vlan_id}")
        vlan_irb_lines.append(f"set interfaces irb.{vlan_id} family inet address {ip_address}")
        vlan_irb_lines.append(f"set vlans v{vlan_id} l3-interface irb.{vlan_id}")

    for interface_prefix in interface_prefixes:
        interface_name = f"{interface_prefix}.0"
        for vlan_id in vlan_ids:
            if access:
                interface_lines.append(f"set interfaces {interface_name} family ethernet-switching interface-mode access vlan members v{vlan_id}")
            elif trunk:
                if native_vlanid and not native_vlanid_configured[interface_prefix]:
                    interface_lines.append(f"set interfaces {interface_name} native-vlan-id {native_vlanid_value}")
                    native_vlanid_configured[interface_prefix] = True
                interface_lines.append(f"set interfaces {interface_name} family ethernet-switching interface-mode trunk vlan members v{vlan_id}")

        # Update base_ip_parts for the next VLAN
        if base_ip_parts[2] == 254:
            base_ip_parts[1] += 1
            base_ip_parts[2] = 0
        else:
            base_ip_parts[2] += 1

    config_lines.extend(vlan_irb_lines)
    config_lines.extend(interface_lines)

    return config_lines



@app.route('/vxlan', methods=['POST'])
@login_required
def vxlan():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Pls login again', 'error')
        return redirect(url_for('index'))
    num_spines = int(request.form['num_spines'])
    num_leafs = int(request.form['num_leafs'])
    spine_ips = [request.form.get(f'spine_ip_{i}', None) for i in range(num_spines)]
    leaf_ips = [request.form.get(f'leaf_ip_{i}', None) for i in range(num_leafs)]
    base_ip_parts = list(map(int, request.form['base_ip_parts'].split('.')))
    last_octet = int(request.form['last_octet'])
    base_vxlan_vni = int(request.form['base_vxlan_vni'])
    base_vxlan_vlan_id = int(request.form['base_vxlan_vlan_id'])
    num_vxlan_configs = int(request.form['num_vxlan_configs'])
    vxlan_filename = request.form['vxlan_filename']
    leaf_base_as= int(request.form['leaf_base_as'])
    spine_base_as= int(request.form['spine_base_as'])
    generate_overlay_config = 'generate_overlay_config' in request.form
    logging.info(generate_overlay_config)
    spine_configs, leaf_configs = generate_vxlan_config(spine_ips, leaf_ips, base_ip_parts, last_octet, base_vxlan_vni,
                                                        base_vxlan_vlan_id, num_vxlan_configs, generate_overlay_config,leaf_base_as,spine_base_as)
    for i, spine_config in enumerate(spine_configs):
        filename = f"spine_{i + 1}_{vxlan_filename}"
        config_file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        with open(config_file_path, "w") as config_file:
            config_file.write("\n".join(spine_config))
    for i, leaf_config in enumerate(leaf_configs):
        filename = f"leaf_{i + 1}_{vxlan_filename}"
        config_file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        with open(config_file_path, "w") as config_file:
            config_file.write("\n".join(leaf_config))
    download_link = True
    #devices = get_router_details_from_csv(os.path.join(current_app.config['UPLOAD_FOLDER'], 'device.csv'))
    devices = get_router_details_from_db()
    return render_template('result_generate_vxlan_config.html',
                       spine_configs=spine_configs, leaf_configs=leaf_configs,
                       download_link=download_link, vxlan_filename=vxlan_filename, enumerate=enumerate, devices=devices)


@app.route('/onboard_devices', methods=['GET', 'POST'])
@login_required
def onboard_devices():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Pls login again', 'error')
        return redirect(url_for('index'))

    devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()

    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No selected file'}), 400
        if file:
            filename = file.filename
            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            added_devices = []
            duplicated_devices = []
            try:
                with open(file_path, 'r') as csvfile:
                    csvreader = csv.DictReader(csvfile)
                    try:
                        for row in csvreader:
                            existing_device = DeviceInfo.query.filter_by(user_id=current_user.id, ip=row['ip']).first()
                            if existing_device:
                                duplicated_devices.append(row['ip'])
                                continue

                            new_device = DeviceInfo(
                                user_id=current_user.id,
                                hostname=row['hostname'],
                                ip=row['ip'],
                                username=row['username'],
                                password=row['password']
                            )
                            db.session.add(new_device)
                            added_devices.append(new_device.hostname)
                    except Exception as e:
                        return jsonify({'success': False, 'error': f'Invalid CSV file format: {str(e)}'}), 400
                    db.session.commit()
                return jsonify({
                    'success': True,
                    'added_devices': added_devices,
                    'duplicated_devices': duplicated_devices
                }), 200
            except csv.Error as e:
                return jsonify({'success': False, 'error': f'Invalid CSV file format: {str(e)}'}), 400
            except ValueError as e:
                return jsonify({'success': False, 'error': str(e)}), 400
    return redirect(url_for('index'))
    #return render_template('onboard_devices.html', devices=devices)


"""@app.route('/onboard_devices', methods=['GET', 'POST'])
@login_required
def onboard_devices():
    if 'UPLOAD_FOLDER' not in current_app.config:
        flash('Please login again', 'error')
        return redirect(url_for('index'))

    devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        if file:
            filename = file.filename
            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            flash(f'{filename} successfully uploaded in upload directory', 'success')

            with open(file_path, 'r') as csvfile:
                csvreader = csv.DictReader(csvfile)
                for row in csvreader:
                    # Check if device IP address already exists in the database for the current user
                    existing_device = DeviceInfo.query.filter_by(user_id=current_user.id, ip=row['ip']).first()
                    if existing_device:
                        flash(f"Device with IP {row['ip']} already exists and will not be added again.", 'error')
                        logging.info(f"Duplicate device IP {row['ip']} found for user {current_user.id}. Skipping addition.")
                        continue

                    # Insert new device into the database
                    new_device = DeviceInfo(
                        user_id=current_user.id,
                        hostname=row['hostname'],
                        ip=row['ip'],
                        username=row['username'],
                        password=row['password']
                    )
                    db.session.add(new_device)
                    logging.info(f"Added device: {new_device.hostname} for user {new_device.user_id}")

                db.session.commit()
            return redirect(url_for('onboard_devices'))

    return render_template('onboard_devices.html', devices=devices)
"""
"""@app.route('/add_device', methods=['POST'])
@login_required
def add_device():
    data = request.json
    logging.info(f"Received data for adding device: {data}")

    hostname = data.get('hostname')
    ip = data.get('ip')
    username = data.get('username')
    password = data.get('password')

    if not hostname or not ip or not username or not password:
        logging.error("Missing required fields")
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    existing_device = DeviceInfo.query.filter_by(ip=ip, user_id=current_user.id).first()
    if existing_device:
        logging.error(f"Device with IP {ip} already exists")
        return jsonify({'success': False, 'message': 'Device with this IP address already exists'}), 400
    new_device = DeviceInfo(
        user_id=current_user.id,
        hostname=hostname,
        ip=ip,
        username=username,
        password=password
    )
    db.session.add(new_device)
    db.session.commit()
    logging.info("Device added successfully")
    return jsonify({'success': True, 'message': 'Device added successfully'})"""

@app.route('/add_device', methods=['POST'])
@login_required
def add_device():
    data = request.get_json()
    hostname = data.get('hostname')
    ip = data.get('ip')
    username = data.get('username')
    password = data.get('password')

    existing_device = DeviceInfo.query.filter_by(ip=ip).first()
    if existing_device:
        print(existing_device)
        return jsonify({'success': False, 'message': 'Device already exists'}), 400

    try:
        new_device = DeviceInfo(
            user_id=current_user.id,
            hostname=hostname,
            ip=ip,
            username=username,
            password=password
        )
        db.session.add(new_device)
        db.session.commit()
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to add device'}), 500



@app.route('/delete_device/<int:device_id>', methods=['POST'])
@login_required
def delete_device(device_id):
    #print("i am here")
    device = DeviceInfo.query.get(device_id)
    if device:
        db.session.delete(device)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Device deleted successfully'})
    return jsonify({'success': False, 'message': 'Device not found'}), 404



@app.route('/download/<filename>', methods=['GET'])
@login_required
def download(filename):
    config_file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    return send_file(config_file_path, as_attachment=True)


@app.route('/users', methods=['GET'])
@login_required
@admin_required
def list_users():
    users = User.query.all()
    return render_template('list_users.html', users=users)

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('list_users'))

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')



if __name__ == '__main__':
    socketio.run(app, debug=True)
