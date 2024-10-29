#routes.py#
from app import login_manager, socketio
from .models import User,DeviceInfo,Topology,GpuSystem,TriggerEvent,GNMIPath,InfluxQuery
from .utils import OnboardDeviceClass, TelemetryUtils, InfluxDBConnectionV2,GNMIConfigBuilder,is_reachable,get_router_details_from_db, admin_required, create_user_folders, setup_user_logging,transfer_file_to_router,get_router_ips_from_csv,get_router_details_from_csv,get_lldp_neighbors,get_next_available_ip,generate_common_config,generate_interface_config,generate_bgp_config,generate_config,check_device_health,check_link_health,generate_bgp_scale_config,generate_vlan_config
from .utils import DeviceConnectorClass, BuildLLDPConnectionClass, VxlanConfigGeneratorClass
from app.config import config
from app.models import User
from . import db
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, current_app, jsonify, send_from_directory,abort
from flask_login import login_user, login_required, logout_user, current_user
from flask import session
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.utils.sw import SW
from lxml import etree
import logging,os, io,csv,time,ipaddress,threading,hashlib
from collections import defaultdict
from functools import wraps
from jnpr.junos.exception import ConnectError, ConnectAuthError, ConfigLoadError, CommitError, LockError, UnlockError,RpcError,RpcTimeoutError,ConnectUnknownHostError
from werkzeug.utils import secure_filename
from jnpr.junos.utils.scp import SCP
import psutil, re, paramiko
from flask_cors import CORS
from ncclient.transport.errors import SSHError
import paramiko,traceback,socket




logging.info(f"current_app.config:: {current_app.config}")
def create_routes(app):
    CORS(app)
    @socketio.on('connect')
    def handle_connect():
        print('Client connected')

    @socketio.on('disconnect')
    def handle_disconnect():
        print('Client disconnected')

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
        try:
            user = User.query.get(user_id)
            if user:
                logging.info(f"User found: {user.username}")
                # Manually delete associated records
                DeviceInfo.query.filter_by(user_id=user.id).delete()
                TriggerEvent.query.filter_by(user_id=user.id).delete()
                Topology.query.filter_by(user_id=user.id).delete()
                logging.info(f"Associated records deleted for user ID {user_id}")

                # Now delete the user
                db.session.delete(user)
                db.session.commit()
                logging.info(f"User with ID {user_id} deleted successfully")
                flash('User deleted successfully.', 'success')
            else:
                flash('User not found.', 'error')
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error deleting user: {str(e)}")
            flash(f'Error deleting user: {str(e)}', 'error')

        return redirect(url_for('list_users'))

    '''@app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))'''

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        # Reset LOG_FOLDER to default when user logs out
        current_app.config['LOG_FOLDER'] = os.path.join(current_app.config['BASE_DIR'], 'logs')
        flash('You have been logged out.', 'success')
        return redirect(url_for('index'))

    '''@app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('index'))  # Redirect if already logged in
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)  # Log in the user
                # Dynamically create user-specific folders after login
                config_name = os.getenv('FLASK_CONFIG') or 'development'
                config_class = config[config_name]
                user_folder, log_folder, telemetry_folder, device_config = config_class().create_user_folders(username)
                # Update app configuration with user-specific folders
                current_app.config['UPLOAD_FOLDER'] = user_folder
                current_app.config['LOG_FOLDER'] = log_folder
                current_app.config['TELEMETRY_FOLDER'] = telemetry_folder
                current_app.config['DEVICE_FOLDER'] = device_config
                # Log the folder setup for the user
                logging.info(f"User-specific folders set up for {username}")
                setup_user_logging(log_folder)  # Set up user-specific logging if required
                #config_class_name.setup_logging(log_folder)
                flash('Login successful!', 'success')
                return redirect(url_for('index'))  # Redirect to main page after login
            else:
                flash('Invalid username or password', 'error')
                return redirect(url_for('index'))

        return render_template('login.html')'''

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('index'))  # Redirect if already logged in

        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)  # Log in the user

                # Dynamically create user-specific folders after login
                config_class_name = os.getenv(
                    'FLASK_CONFIG') or 'development'  # Ensure config_class_name is set correctly
                config_class = config[config_class_name]()  # Correctly instantiate the config class

                # Create user-specific folders and set up logging
                user_folder, log_folder, telemetry_folder, device_config = config_class.create_user_folders(username)

                # Update app configuration with user-specific folders
                current_app.config['UPLOAD_FOLDER'] = user_folder
                current_app.config['LOG_FOLDER'] = log_folder
                current_app.config['TELEMETRY_FOLDER'] = telemetry_folder
                current_app.config['DEVICE_FOLDER'] = device_config

                # Set up user-specific logging
                config_class.setup_logging(log_folder)

                flash('Login successful!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password', 'error')

        return render_template('login.html')

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            role = request.form.get('role', 'user')
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already exists. Please choose a different one.', 'error')
                return redirect(url_for('signup'))
            new_user = User(username=username)
            new_user.password = password  # This uses the password setter
            new_user.role = role
            # Add the new user to the database
            try:
                db.session.add(new_user)
                db.session.commit()
                flash('Signup successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()  # Roll back in case of error
                flash(f'Error: {str(e)}', 'error')
                return redirect(url_for('signup'))
        return render_template('signup.html')

    @app.route('/debug_log')
    @login_required
    def debug_log():
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash('Pls login again', 'error')
            return redirect(url_for('index'))
        log_file_path = os.path.join(current_app.config['LOG_FOLDER'], 'debug.log')
        print(log_file_path)
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


    #*******************************  Main APP START **************************##



    @app.route('/test2')
    def test2():
        return render_template('test2.html')  # Renders the HTML form

    @app.route('/test', methods=['POST'])
    def test():
        return

    @app.route('/onboardDevicesForm')
    def onboardDevicesForm():
        return render_template('onboardDevices_Form.html')

    @app.route('/vxlanForm')
    def vxlanForm():
        return render_template('vxlan_form.html')  # Renders the HTML form

    @app.route('/bgpConfigForm')
    def bgpConfigForm():
        return render_template('bgpConfig_Form.html')

    @app.route('/underlayConfigForm')
    def underlayConfigForm():
        return render_template('underlayConfig_Form.html')

    @app.route('/vlanConfigForm')
    def vlanConfigForm():
        return render_template('vlanConfig_Form.html')

    @app.route('/deviceTelemetryForm')
    def deviceTelemetryForm():
        return render_template('deviceTelemetry_Form.html')

    @app.route('/uploadConfigForm')
    def uploadConfigForm():
        return render_template('uploadConfig_Form.html')


    @app.route('/triggerEventsForm', methods=['GET'])
    def triggerEventsForm():
        events = TriggerEvent.query.filter_by(user_id=current_user.id).all()
        return render_template('triggerEvents_Form.html', events=events)

    @app.route('/start_telemetry_stream', methods=['POST'])
    @login_required
    def start_telemetry_stream():
        gnmi_utility = TelemetryUtils(current_app)

        # Determine selected devices
        selected_device = request.form.get('device_ip')
        devices = []

        if selected_device == 'all':
            # Query the database for all devices for the current user
            devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
            devices = [{'hostname': device.hostname, 'ip': device.ip, 'username': device.username,
                        'password': device.password} for device in devices]
        else:
            # Query the database for the specific selected device for the current user
            device = DeviceInfo.query.filter_by(user_id=current_user.id, hostname=selected_device).first()
            if device:
                devices = [{'hostname': device.hostname, 'ip': device.ip, 'username': device.username,
                            'password': device.password}]
            else:
                return jsonify({"status": "error", "message": "Selected device not found."})

        telemetry_port = request.form.get('telemetry_port')
        response = gnmi_utility.start_telemetry_stream(devices, telemetry_port)
        return jsonify(response)



    @app.route('/stop_telemetry_stream', methods=['POST'])
    @login_required
    def stop_telemetry_stream():
        gnmi_utility = TelemetryUtils(current_app)
        response = gnmi_utility.stop_stream()
        return jsonify(response)

    @app.route('/check_telemetry_status', methods=['GET'])
    @login_required
    def check_telemetry_status():
        logging.debug("Checking telemetry status...")
        pid = current_user.telemetry_pid
        if pid:
            try:
                process = psutil.Process(pid)
                if process.is_running():
                    logging.debug("Telemetry process is running.")
                    return jsonify({"status": "running"})
                else:
                    logging.debug("Telemetry process is not running.")
                    logging.debug("Telemetry process is not running.")
                    return jsonify({"status": "stopped"})
            except psutil.NoSuchProcess:
                logging.debug("No such process, cleaning up.")
                current_user.telemetry_pid = None
                db.session.commit()
                return jsonify({"status": "stopped"})
        logging.debug("No telemetry PID found.")
        return jsonify({"status": "stopped"})

    @app.route('/check_files_exist', methods=['GET'])
    @login_required
    def check_files_exist():
        telemetry_folder = current_app.config['TELEMETRY_FOLDER']
        user_folder = os.path.join(telemetry_folder)  # Ensure this is correct
        gnmi_config_path = os.path.join(user_folder, 'gnmi-config.yaml')
        logging.info(f"check_files_exist -routes.py- {gnmi_config_path}")
        telemetry_log_path = os.path.join(user_folder, 'telemetry_debug.log')
        logging.info(f"check_files_exist -routes.py- {telemetry_log_path}")
        gnmi_config_exists = os.path.exists(gnmi_config_path)
        telemetry_log_exists = os.path.exists(telemetry_log_path)

        files_exist = {
            "gnmi_config_exists": gnmi_config_exists,
            "gnmi_config_path": f"/files/{current_user.username}/{os.path.basename(gnmi_config_path)}" if gnmi_config_exists else None,
            "telemetry_log_exists": telemetry_log_exists,
            "telemetry_log_path": f"/files/{current_user.username}/{os.path.basename(telemetry_log_path)}" if telemetry_log_exists else None,
        }

        logging.info(f"Files exist response-routes.py: {files_exist}")
        return jsonify(files_exist)

    @app.route('/files/<username>/<filename>', methods=['GET'])
    @login_required
    def serve_file(username, filename):
        # Ensure that the requested username matches the logged-in user's username
        if username != current_user.username:
            abort(403, description="Access forbidden: You cannot access files from another user.")

        # Construct the telemetry folder path
        telemetry_folder = current_app.config['TELEMETRY_FOLDER']
        user_folder = os.path.join(telemetry_folder)  # Use telemetry_folder directly

        # Construct the full file path
        file_path = os.path.join(user_folder, filename)
        logging.info(f"file_path: routep.py-serve_file: Attempting to serve file from: {file_path}")
        # Log the absolute path and directory contents
        absolute_file_path = os.path.abspath(file_path)
        logging.info(f"absolute_file_path: routep.py-serve_file: Attempting to serve file from: {absolute_file_path}")
        if os.path.exists(user_folder):
            logging.info(f"Contents of directory : serve_file-routep.py:{user_folder}: {os.listdir(user_folder)}")
        else:
            logging.error(f"Contents of directory- serve_file-routep.py:: Directory does not exist: {user_folder}")
            abort(404, description="User directory not found")

        # Double-check the file exists where expected
        if not os.path.exists(file_path):
            logging.error(f"File not found:serve_file-routep.py{file_path}")
            abort(404, description="Resource not found")

        try:
            # Serve the file using the absolute path
            return send_file(absolute_file_path, as_attachment=(filename != 'telemetry_debug.log'))
        except Exception as e:
            logging.error(f"Error sending file: {e}")
            abort(500, description="Internal server error")



    @app.route('/view_telemetry_log', methods=['GET'])
    @login_required
    def view_telemetry_log():
        try:
            telemetry_folder = os.path.abspath(current_app.config['TELEMETRY_FOLDER'])  # Ensure absolute path
            # Ensure that the log file is in the base telemetry directory, without adding username
            log_file_path = os.path.join(telemetry_folder, "telemetry_debug.log")
            logging.info(f"view_telemetry_log: {log_file_path}")
            absolute_log_path = os.path.abspath(log_file_path)
            logging.info(f"Absolute log file path: {absolute_log_path}")
            if os.path.exists(log_file_path):
                return send_file(log_file_path, as_attachment=False)
            else:
                logging.error(f"Log file not found at: {absolute_log_path}")
                abort(404, description="Log file not found")
        except Exception as e:
            logging.error(f"Error serving log file: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route('/get_measurements')
    def get_measurements():
        source = request.args.get('source')
        # Fetch measurements based on the source
        influx_connection = InfluxDBConnectionV2()
        measurements = influx_connection.get_measurements_for_device(source)
        # Return the measurements as JSON
        return jsonify({'measurements': measurements})

    @app.route('/get_columns_and_interfaces')
    def get_columns_and_interfaces():
        source = request.args.get('source')

        influx_connection = InfluxDBConnectionV2()

        # Query to get columns for the source
        columns_query = influx_connection.query_columns_for_source(source_filter=source)

        # Query to get interfaces for the source
        interface_names_query = influx_connection.query_interface_names(source_filter=source)

        columns = []
        interfaces = []

        if columns_query:
            try:
                series = columns_query['results'][0]['series'][0]
                columns = [col.split('/')[-1] for col in series['columns']]
            except (KeyError, IndexError):
                columns = []

        if interface_names_query:
            try:
                series = interface_names_query['results'][0]['series'][0]
                interfaces = [row[1] for row in series['values']]
            except (KeyError, IndexError):
                interfaces = []

        return jsonify({'columns': columns, 'interfaces': interfaces})

    @app.route('/delete_measurement', methods=['POST'])
    @login_required
    def delete_measurement():
        try:
            data = request.get_json()
            measurement = data.get('measurement')

            if not measurement:
                return jsonify({"status": "error", "message": "No measurement provided"}), 400

            influx_connection = InfluxDBConnectionV2()
            success = influx_connection.delete_measurement(measurement)

            if success:
                return jsonify({"status": "success", "message": f"Measurement '{measurement}' deleted successfully"})
            else:
                return jsonify({"status": "error", "message": f"Failed to delete measurement '{measurement}'"})

        except Exception as e:
            logging.error(f"Error deleting measurement: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route('/save_seclected_influx_query', methods=['POST'])
    @login_required
    def save_influx_query():
        try:
            data = request.get_json()
            logging.info(f"data: save_seclected_influx_query-routes.py- {data}")
            measurement = data.get('measurement')
            columns = ','.join(data.get('selected_columns', []))
            interface_columns = ','.join(data.get('selected_interface_columns', []))  # Interface columns

            # Check if a query already exists for this user and measurement
            existing_query = InfluxQuery.query.filter_by(user_id=current_user.id, measurement=measurement).first()

            if existing_query:
                # Update the existing query
                logging.info(f"Updating existing query for measurement: {measurement}")
                existing_query.columns = columns
                existing_query.interface_columns = interface_columns  # Update interface query
            else:
                # Save a new query
                logging.info(f"Creating new query for measurement: {measurement}")
                influx_query = InfluxQuery(
                    user_id=current_user.id,
                    measurement=measurement,
                    columns=columns,
                    interface_columns=interface_columns  # Store interface query
                )
                db.session.add(influx_query)

            db.session.commit()

            logging.info(f"Confirmed saved columns: {columns} and interface columns: {interface_columns}")
            return jsonify({"status": "success", "message": "Query saved successfully!"})
        except Exception as e:
            logging.error(f"Error saving query: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500

    """@app.route('/save_seclected_influx_query', methods=['POST'])
    @login_required
    def save_influx_query():
        try:
            data = request.get_json()
            logging.info(f"data: save_seclected_influx_query-routes.py- {data}")
            measurement = data.get('measurement')
            columns = ','.join(data.get('selected_columns', []))

            # Check if a query already exists for this user and measurement
            existing_query = InfluxQuery.query.filter_by(user_id=current_user.id, measurement=measurement).first()

            if existing_query:
                # Update the existing query
                logging.info(f"Updating existing query for measurement: {measurement}")
                existing_query.columns = columns
            else:
                # Save a new query
                logging.info(f"Creating new query for measurement: {measurement}")
                influx_query = InfluxQuery(
                    user_id=current_user.id,
                    measurement=measurement,
                    columns=columns
                )
                db.session.add(influx_query)

            db.session.commit()

            logging.info(f"Confirmed saved columns: {columns}")
            return jsonify({"status": "success", "message": "Query saved successfully!"})
        except Exception as e:
            logging.error(f"Error saving query: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500"""
    """@app.route('/interface_counters', methods=['GET', 'POST'])
    @login_required
    def interface_counters():
        influx_connection = InfluxDBConnectionV2()

        # Fetch unique sources (IP addresses) from the DeviceInfo table
        sources = [device.ip for device in DeviceInfo.query.with_entities(DeviceInfo.ip).distinct()]

        # Retrieve the user's selected source, measurement, interfaces, and columns
        selected_source = request.json.get('source') if request.is_json else request.form.get('source', sources[
            0] if sources else '')
        selected_measurement = request.json.get('measurement') if request.is_json else request.form.get('measurement',
                                                                                                        '')
        selected_interfaces = request.json.get('interfaces') if request.is_json else request.form.getlist('interfaces')
        selected_columns = request.json.get('selectedquery', []) if request.is_json else request.form.getlist(
            'selectedquery[]')
        selected_Interface_columns = request.json.get('selected_Interface_columns', []) if request.is_json else request.form.getlist(
            'selectedInterfaces_query[]')

        # Initialize the limit variable safely
        if request.is_json:
            limit = int(request.json.get('limit', 10))
        else:
            try:
                limit = int(request.form.get('limit', 10))
            except ValueError:
                limit = 10

        # Debugging: Log the selected data
        logging.info(f"Selected Source: {selected_source}")
        logging.info(f"Selected Measurement: {selected_measurement}")
        logging.info(f"Selected Interfaces: {selected_interfaces}")
        logging.info(f"Selected Columns: {selected_columns}")
        logging.info(f"Selected Interface Columns: {selected_Interface_columns}")
        logging.info(
            f"Querying InfluxDB with limit: {limit}, source: {selected_source}, interfaces: {selected_interfaces}, measurement: {selected_measurement}, columns: {selected_columns}, selected_Interface_columns: {selected_Interface_columns}")

        if request.method == 'POST':
            if request.is_json:
                # Query InfluxDB for the actual interface counter data using the selected measurement and columns
                result = influx_connection.query_interface_counters(
                    limit=limit,
                    source_filter=selected_source,
                    interfaces_filter=selected_interfaces,  # Use the selected interfaces as the filter
                    measurement_filter=selected_measurement
                )

                logging.info(f"Influx Query Result: {result}")
                if not result or len(result) == 0 or not result.get('results', []) or 'series' not in result['results'][
                    0]:
                    return jsonify({"columns": [], "values": []})

                try:
                    series = result['results'][0]['series'][0]
                    all_columns = series['columns']
                    values = series['values']

                    # Filter the columns based on selected columns if necessary
                    filtered_indices = [i for i, col in enumerate(all_columns) if
                                        col.split('/')[-1] in selected_columns]
                    # Always include 'source' and 'interface_name' columns if they exist
                    if 'source' in all_columns:
                        source_index = all_columns.index('source')
                        if source_index not in filtered_indices:
                            filtered_indices.insert(0, source_index)
                    if 'interface_name' in all_columns:
                        interface_name_index = all_columns.index('interface_name')
                        if interface_name_index not in filtered_indices:
                            filtered_indices.insert(1, interface_name_index)

                    filtered_columns = [all_columns[i].split('/')[-1] for i in filtered_indices]
                    filtered_values = [[row[i] for i in filtered_indices] for row in values]

                    return jsonify({"columns": filtered_columns, "values": filtered_values})
                except (KeyError, IndexError, ValueError) as e:
                    logging.error(f"Error processing data: {e}")
                    return jsonify({"columns": [], "values": []})

            # Handle deletion of the selected measurement
            if 'delete_measurement' in request.form:
                if selected_measurement:
                    success = influx_connection.delete_measurement(selected_measurement)
                    message = f"Measurement '{selected_measurement}' deleted successfully." if success else f"Failed to delete measurement '{selected_measurement}'."
                    return render_template('interface_telemetry.html', columns=[], values=[], message=message,
                                           sources=sources, selected_source=selected_source,
                                           measurement_types=[selected_measurement],
                                           selected_measurement=selected_measurement,
                                           all_interfaces=[], selected_query_columns=[], limit=10)

            # Check if a measurement is selected
            if not selected_measurement:
                return render_template('interface_telemetry.html', columns=[], values=[],
                                       message="A measurement must be selected.",
                                       sources=sources, selected_source=selected_source,
                                       measurement_types=[selected_measurement],
                                       selected_measurement=selected_measurement,
                                       all_interfaces=[], selected_query_columns=[], limit=10)

            # Query InfluxDB to get distinct interface names for the selected source and measurement
            interface_names_query = influx_connection.query_interface_names(
                source_filter=selected_source,
                measurement_filter=selected_measurement
            )

            # Initialize interface_names to an empty list in case the query fails or returns no results
            interface_names = []
            if interface_names_query and 'results' in interface_names_query and 'series' in \
                    interface_names_query['results'][0]:
                try:
                    series = interface_names_query['results'][0]['series'][0]
                    interface_names = [row[1] for row in series['values']]
                except (KeyError, IndexError):
                    interface_names = []

            # Query InfluxDB for the actual interface counter data using the selected measurement
            result = influx_connection.query_interface_counters(
                limit=limit,
                source_filter=selected_source,
                interfaces_filter=selected_interfaces,
                measurement_filter=selected_measurement
            )
            logging.info(f"Query Result: {result}")

            if not result or len(result) == 0 or not result.get('results', []) or 'series' not in result['results'][0]:
                return render_template('interface_telemetry.html', columns=[], values=[], message="No data available.",
                                       sources=sources, selected_source=selected_source,
                                       measurement_types=[selected_measurement],
                                       selected_measurement=selected_measurement,
                                       all_interfaces=interface_names, selected_query_columns=[], limit=limit)

            try:
                series = result['results'][0]['series'][0]
                all_columns = series['columns']
                values = series['values']

                # Extract the last part after the '/' in each column name
                processed_columns = [col.split('/')[-1] for col in all_columns]

                # Ensure 'source' is the first column and 'interface_name' is the second column
                source_index = all_columns.index('source') if 'source' in all_columns else None
                interface_name_index = all_columns.index('interface_name') if 'interface_name' in all_columns else None

                # Reorder columns: first 'source', then 'interface_name', then the selected columns
                new_columns_order = []
                if source_index is not None:
                    new_columns_order.append(processed_columns[source_index])
                if (interface_name_index is not None and interface_name_index not in new_columns_order):
                    new_columns_order.append(processed_columns[interface_name_index])

                new_columns_order += [col for col in processed_columns if col not in new_columns_order and (
                        not selected_columns or col in selected_columns)]

                columns = new_columns_order

                # Reorder values according to the new column order
                reordered_values = []
                for value_row in values:
                    reordered_row = []
                    for column in columns:
                        column_index = processed_columns.index(column) if column in processed_columns else None
                        reordered_row.append(value_row[column_index] if column_index is not None else None)
                    reordered_values.append(reordered_row)
                values = reordered_values

            except (KeyError, IndexError, ValueError) as e:
                logging.error(f"Error processing data: {e}")
                return render_template('interface_telemetry.html', columns=[], values=[], message="No data available.",
                                       sources=sources, selected_source=selected_source,
                                       measurement_types=[selected_measurement],
                                       selected_measurement=selected_measurement,
                                       all_interfaces=interface_names, selected_query_columns=[], limit=limit)

            # Load the most recent saved query for the selected measurement from InfluxQuery table
            saved_query = InfluxQuery.query.filter_by(user_id=current_user.id,
                                                      measurement=selected_measurement).order_by(
                InfluxQuery.id.desc()).first()

            logging.info(f"saved_query: interface_counters-routes.py - {saved_query}")
            selected_query_columns = saved_query.columns.split(',') if saved_query else []
            logging.info(f"selected_query_columns: interface_counters-routes.py - {selected_query_columns}")

            return render_template('interface_telemetry.html', columns=columns, values=values, message=None,
                                   sources=sources, selected_source=selected_source,
                                   measurement_types=[selected_measurement],
                                   selected_measurement=selected_measurement, all_columns=processed_columns,
                                   all_interfaces=interface_names, selected_interfaces=selected_interfaces,
                                   selected_query_columns=selected_query_columns, limit=limit)

        # Handle GET request (load the initial form)
        return render_template(
            'interface_telemetry.html',
            columns=[],
            values=[],
            message=None,
            sources=sources,
            selected_source=selected_source,
            measurement_types=[selected_measurement],
            selected_measurement=selected_measurement,
            all_interfaces=[],
            selected_query_columns=[],
            limit=10
        )"""

    @app.route('/interface_counters', methods=['GET', 'POST'])
    @login_required
    def interface_counters():
        influx_connection = InfluxDBConnectionV2()

        # Fetch unique sources (IP addresses) from the DeviceInfo table
        sources = [device.ip for device in DeviceInfo.query.with_entities(DeviceInfo.ip).distinct()]

        # Retrieve the user's selected source, measurement, interfaces, and columns
        selected_source = request.json.get('source') if request.is_json else request.form.get('source', sources[
            0] if sources else '')
        selected_measurement = request.json.get('measurement') if request.is_json else request.form.get('measurement',
                                                                                                        '')
        selected_interfaces = request.json.get('interfaces') if request.is_json else request.form.getlist('interfaces')
        selected_columns = request.json.get('selectedquery', []) if request.is_json else request.form.getlist(
            'selectedquery[]')
        selected_Interface_columns = request.json.get('selected_Interface_columns',
                                                      []) if request.is_json else request.form.getlist(
            'selectedInterfacequery[]')

        # Initialize the limit variable safely
        if request.is_json:
            limit = int(request.json.get('limit', 10))
        else:
            try:
                limit = int(request.form.get('limit', 10))
            except ValueError:
                limit = 10

        # Debugging: Log the selected data
        logging.info(f"Selected Source: {selected_source}")
        logging.info(f"Selected Measurement: {selected_measurement}")
        logging.info(f"Selected Interfaces: {selected_interfaces}")
        logging.info(f"Selected Columns: {selected_columns}")
        logging.info(f"Selected Interface Columns: {selected_Interface_columns}")
        logging.info(
            f"Querying InfluxDB with limit: {limit}, source: {selected_source}, interfaces: {selected_interfaces}, measurement: {selected_measurement}, columns: {selected_columns}, selected_Interface_columns: {selected_Interface_columns}")

        if request.method == 'POST':
            if request.is_json:
                # Query InfluxDB for the actual interface counter data using the selected measurement and columns
                result = influx_connection.query_interface_counters(
                    limit=limit,
                    source_filter=selected_source,
                    interfaces_filter=selected_interfaces,  # Use the selected interfaces as the filter
                    measurement_filter=selected_measurement
                )

                logging.info(f"Influx Query Result: {result}")
                if not result or len(result) == 0 or not result.get('results', []) or 'series' not in result['results'][
                    0]:
                    return jsonify({"columns": [], "values": []})

                try:
                    series = result['results'][0]['series'][0]
                    all_columns = series['columns']
                    values = series['values']

                    # Filter the columns based on selected columns if necessary
                    filtered_indices = [i for i, col in enumerate(all_columns) if
                                        col.split('/')[-1] in selected_columns]
                    # Always include 'source' and 'interface_name' columns if they exist
                    if 'source' in all_columns:
                        source_index = all_columns.index('source')
                        if source_index not in filtered_indices:
                            filtered_indices.insert(0, source_index)
                    if 'interface_name' in all_columns:
                        interface_name_index = all_columns.index('interface_name')
                        if interface_name_index not in filtered_indices:
                            filtered_indices.insert(1, interface_name_index)

                    filtered_columns = [all_columns[i].split('/')[-1] for i in filtered_indices]
                    filtered_values = [[row[i] for i in filtered_indices] for row in values]

                    #return jsonify({"columns": filtered_columns, "values": filtered_values})
                    # Return filtered columns, values, and the selected interface columns
                    return jsonify({
                        "columns": filtered_columns,
                        "values": filtered_values,
                        "selected_Interface_columns": selected_Interface_columns
                    })
                except (KeyError, IndexError, ValueError) as e:
                    logging.error(f"Error processing data: {e}")
                    return jsonify({"columns": [], "values": []})

            # Handle deletion of the selected measurement
            if 'delete_measurement' in request.form:
                if selected_measurement:
                    success = influx_connection.delete_measurement(selected_measurement)
                    message = f"Measurement '{selected_measurement}' deleted successfully." if success else f"Failed to delete measurement '{selected_measurement}'."
                    return render_template('interface_telemetry.html', columns=[], values=[], message=message,
                                           sources=sources, selected_source=selected_source,
                                           measurement_types=[selected_measurement],
                                           selected_measurement=selected_measurement,
                                           all_interfaces=[], selected_query_columns=[], limit=10)

            # Check if a measurement is selected
            if not selected_measurement:
                return render_template('interface_telemetry.html', columns=[], values=[],
                                       message="A measurement must be selected.",
                                       sources=sources, selected_source=selected_source,
                                       measurement_types=[selected_measurement],
                                       selected_measurement=selected_measurement,
                                       all_interfaces=[], selected_query_columns=[], limit=10)

            # Query InfluxDB to get distinct interface names for the selected source and measurement
            interface_names_query = influx_connection.query_interface_names(
                source_filter=selected_source,
                measurement_filter=selected_measurement
            )

            # Initialize interface_names to an empty list in case the query fails or returns no results
            interface_names = []
            if interface_names_query and 'results' in interface_names_query and 'series' in \
                    interface_names_query['results'][0]:
                try:
                    series = interface_names_query['results'][0]['series'][0]
                    interface_names = [row[1] for row in series['values']]
                except (KeyError, IndexError):
                    interface_names = []

            # Query InfluxDB for the actual interface counter data using the selected measurement
            result = influx_connection.query_interface_counters(
                limit=limit,
                source_filter=selected_source,
                interfaces_filter=selected_interfaces,
                measurement_filter=selected_measurement
            )
            logging.info(f"Query Result: {result}")

            if not result or len(result) == 0 or not result.get('results', []) or 'series' not in result['results'][0]:
                return render_template('interface_telemetry.html', columns=[], values=[], message="No data available.",
                                       sources=sources, selected_source=selected_source,
                                       measurement_types=[selected_measurement],
                                       selected_measurement=selected_measurement,
                                       all_interfaces=interface_names, selected_query_columns=[], limit=limit)

            try:
                series = result['results'][0]['series'][0]
                all_columns = series['columns']
                values = series['values']

                # Extract the last part after the '/' in each column name
                processed_columns = [col.split('/')[-1] for col in all_columns]

                # Ensure 'source' is the first column and 'interface_name' is the second column
                source_index = all_columns.index('source') if 'source' in all_columns else None
                interface_name_index = all_columns.index('interface_name') if 'interface_name' in all_columns else None

                # Reorder columns: first 'source', then 'interface_name', then the selected columns
                new_columns_order = []
                if source_index is not None:
                    new_columns_order.append(processed_columns[source_index])
                if (interface_name_index is not None and interface_name_index not in new_columns_order):
                    new_columns_order.append(processed_columns[interface_name_index])

                new_columns_order += [col for col in processed_columns if col not in new_columns_order and (
                        not selected_columns or col in selected_columns)]

                columns = new_columns_order

                # Reorder values according to the new column order
                reordered_values = []
                for value_row in values:
                    reordered_row = []
                    for column in columns:
                        column_index = processed_columns.index(column) if column in processed_columns else None
                        reordered_row.append(value_row[column_index] if column_index is not None else None)
                    reordered_values.append(reordered_row)
                values = reordered_values

            except (KeyError, IndexError, ValueError) as e:
                logging.error(f"Error processing data: {e}")
                return render_template('interface_telemetry.html', columns=[], values=[], message="No data available.",
                                       sources=sources, selected_source=selected_source,
                                       measurement_types=[selected_measurement],
                                       selected_measurement=selected_measurement,
                                       all_interfaces=interface_names, selected_query_columns=[], limit=limit)

            # Load the most recent saved query for the selected measurement from InfluxQuery table
            saved_query = InfluxQuery.query.filter_by(user_id=current_user.id,
                                                      measurement=selected_measurement).order_by(
                InfluxQuery.id.desc()).first()


            selected_query_columns = saved_query.columns.split(',') if saved_query else []
            logging.info(f"selected_query_columns: interface_counters-routes.py - {selected_query_columns}")
            selected_Interface_columns = saved_query.interface_columns.split(
                ',') if saved_query and saved_query.interface_columns else []
            logging.info(f"selected_query_columns: interface_counters-routes.py - {selected_Interface_columns}")

            return render_template('interface_telemetry.html', columns=columns, values=values, message=None,
                                   sources=sources, selected_source=selected_source,
                                   measurement_types=[selected_measurement],
                                   selected_measurement=selected_measurement, all_columns=processed_columns,
                                   all_interfaces=interface_names, selected_interfaces=selected_interfaces,
                                   selected_query_columns=selected_query_columns,  selectedInterface_columns=selected_Interface_columns,limit=limit)

        # Handle GET request (load the initial form)
        return render_template(
            'interface_telemetry.html',
            columns=[],
            values=[],
            message=None,
            sources=sources,
            selected_source=selected_source,
            measurement_types=[selected_measurement],
            selected_measurement=selected_measurement,
            all_interfaces=[],
            selected_query_columns=[],
            selectedInterface_columns=[],
            limit=10
        )

    @app.route('/save_gnmi_paths', methods=['POST'])
    @login_required
    def save_gnmi_paths():
        try:
            data = request.get_json()
            gnmi_paths_str = data.get('gnmi_paths', '')
            gnmi_paths = gnmi_paths_str.split(',')

            # Clear existing paths for the user
            GNMIPath.query.filter_by(user_id=current_user.id).delete()

            # Save new paths
            for path in gnmi_paths:
                if path.strip():  # Avoid saving empty paths
                    new_path = GNMIPath(user_id=current_user.id, path=path.strip())
                    db.session.add(new_path)

            db.session.commit()
            return jsonify({"status": "success", "message": "GNMI paths saved successfully"})
        except Exception as e:
            logging.error(f"Error saving GNMI paths: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route('/get_gnmi_paths')
    @login_required
    def get_gnmi_paths():
        try:
            # Retrieve paths from the database
            gnmi_paths = GNMIPath.query.filter_by(user_id=current_user.id).all()
            paths_list = [path.path for path in gnmi_paths]
            return jsonify({"status": "success", "paths": paths_list})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500



    @app.route('/gnmi_subscription_form')
    @login_required
    def gnmi_subscription_form():
        user_id = current_user.id
        existing_paths = [path.path for path in GNMIPath.query.filter_by(user_id=user_id).all()]
        gnmi_paths_str = ','.join(existing_paths)

        return render_template('index.html', existing_paths=gnmi_paths_str)



    @app.route('/gnmi_subscription', methods=['POST'])
    @login_required
    def gnmi_subscription():
        try:
            # Retrieve form data
            gnmi_server = request.form.get('gnmi_server')
            device_ip = request.form.get('device_ip') or request.form.get('device_address')
            gnmi_paths = request.form.get('gnmi_paths', '').split(',')  # Split the comma-separated paths
            subscription_mode = request.form.get('subscription_mode')
            sample_interval = request.form.get('sample_interval')
            telemetry_port = request.form.get('telemetry_port')
            influx_connection = InfluxDBConnectionV2()

            # Initialize the GNMIConfigBuilder
            config_builder = GNMIConfigBuilder(
                influx_token=influx_connection.token,
                gnmi_server=gnmi_server
            )

            # Get devices and add to the config builder
            if device_ip.lower() == 'all':
                devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
                for device in devices:
                    config_builder.add_device(
                        target=device.hostname,
                        port=telemetry_port,
                        address=device.ip,
                        username=device.username,
                        password=device.password,
                        paths=gnmi_paths,
                        subscription_mode=subscription_mode,
                        sample_interval=sample_interval
                    )
            else:
                config_builder.add_device(
                    target=device_ip,
                    port=telemetry_port,
                    address=device_ip,
                    username=request.form.get('username'),
                    password=request.form.get('password'),
                    paths=gnmi_paths,
                    subscription_mode=subscription_mode,
                    sample_interval=sample_interval
                )

            # Build the GNMI config YAML
            gnmi_config_yaml = config_builder.build_config()

            # Save the configuration to a file in the user's specific folder
            #user_folder = os.path.join(current_app.config['TELEMETRY_FOLDER'], current_user.username)
            user_folder = os.path.join(current_app.config['TELEMETRY_FOLDER'])
            os.makedirs(user_folder, exist_ok=True)
            config_file_name = 'gnmi-config.yaml'
            config_file_path = os.path.join(user_folder, config_file_name)
            logging.info(f"Saving GNMI config to {config_file_path}")

            config_builder.save_to_file(config_file_path)

            # Generate the download link
            download_link = url_for('download_gnmi_config', filename=config_file_name, _external=True)
            logging.info(f"Generated download link: {download_link}")

            # Return success response with the configuration and download link
            return jsonify({
                "status": "success",
                "message": "GNMI configuration generated successfully",
                "config": gnmi_config_yaml,
                "download_link": download_link
            })
        except Exception as e:
            logging.error(f"Error during GNMI subscription: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route('/download_gnmi_config/<filename>', methods=['GET'])
    @login_required
    def download_gnmi_config(filename):
        try:
            # Construct the correct path using the user's specific directory
            #telemetry_folder = current_app.config['TELEMETRY_FOLDER']
            telemetry_folder = os.path.abspath(current_app.config['TELEMETRY_FOLDER'])
            # Ensure that the username is appended only once
            #user_folder = os.path.join(telemetry_folder, current_user.username)
            user_folder = os.path.join(telemetry_folder)
            file_path = os.path.join(user_folder, filename)
            #file_path = os.path.join(user_folder, filename)
            logging.info(f"Attempting to send file from: {file_path}")
            # Check if the file actually exists at the constructed path
            if not os.path.isfile(file_path):
                logging.error(f"File not found: {file_path}")
                return jsonify({"status": "error", "message": "File not found"}), 404
            # Serve the file from the user's directory
            #return send_from_directory(user_folder, filename, as_attachment=True)
            return send_file(file_path, as_attachment=True)
        except Exception as e:
            logging.error(f"Error during file download: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500



    @app.route('/get_gpu_systems', methods=['GET'])
    def get_gpu_systems():
        try:
            gpu_systems = GpuSystem.query.all()
            systems_data = []
            for system in gpu_systems:
                # Check if the system is reachable
                if not is_reachable(system.node_ip):
                    system.color = 'red'  # Set color to red if not reachable
                    db.session.commit()  # Save the change to the database
                else:
                    system.color = 'green'  # Set color to green if reachable
                    db.session.commit()  # Save the change to the database

                systems_data.append({
                    'id': system.id,
                    'node_ip': system.node_ip,
                    'user': system.user,
                    'password': system.password,
                    'color': system.color  # Ensure the color is sent in the response
                })
            return jsonify({'status': 'success', 'gpu_systems': systems_data})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)})

    # Endpoint to onboard a GPU node and store it in the database
    @app.route('/gpu_onboarding', methods=['POST'])
    def gpu_onboarding():
        node_ip = request.form['node_ip']
        user = request.form['user']
        password = request.form['password']
        # Check if the system already exists
        existing_system = GpuSystem.query.filter_by(node_ip=node_ip, user=user).first()
        if existing_system:
            return jsonify({"status": "error", "message": f"Node {node_ip} with user {user} is already onboarded."})
        try:
            new_system = GpuSystem(node_ip=node_ip, user=user, password=password)
            db.session.add(new_system)
            db.session.commit()
            return jsonify(
                {"status": "success", "message": f"Node {node_ip} onboarded successfully.", "system_id": new_system.id})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)})



    @app.route('/update_gpu_system', methods=['POST'])
    def update_gpu_system():
        try:
            system_id = request.form.get('system_id')
            node_ip = request.form.get('node_ip')
            user = request.form.get('user')
            password = request.form.get('password')
            # Update the GPU system in the database
            gpu_system = GpuSystem.query.get(system_id)
            gpu_system.node_ip = node_ip
            gpu_system.user = user
            gpu_system.password = password
            db.session.commit()
            return jsonify({'status': 'success'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)})

    @app.route('/delete_gpu_system/<int:id>', methods=['DELETE'])
    def delete_gpu_system(id):
        try:
            gpu_system = GpuSystem.query.get(id)
            if gpu_system:
                db.session.delete(gpu_system)
                db.session.commit()
                return jsonify({'status': 'success'})
            else:
                return jsonify({'status': 'error', 'message': 'GPU system not found'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)})

    @app.route('/gpu_monitoring', methods=['POST'])
    def gpu_monitoring():
        logging.info("gpu_monitoring endpoint was called")
        try:
            # Create an instance of the InfluxDB v2 connection class
            influx_connection = InfluxDBConnectionV2()
            logging.info("InfluxDBConnectionV2 initialized successfully")

            # Retrieve JSON data from the request
            data = request.get_json()
            logging.info(f"Received data: {data}")
            if not data:
                logging.error("No data provided in the request")
                return jsonify({"status": "error", "message": "No data provided"}), 400

            # Get the record limit from the request data or default to 10
            record_limit = data.get('limit', 10)
            logging.info(f"Record limit: {record_limit}")
            selected_date = data.get('date')

            # Get the list of device hosts from InfluxDB
            device_hosts = influx_connection.get_device_hosts()
            logging.info(f"Device hosts: {device_hosts}")
            if not device_hosts:
                logging.info("No device hosts found")
                return jsonify({"status": "success", "metrics": [], "message": "No device hosts found"}), 200

            # Query the metrics
            result = influx_connection.query_metrics(device_hosts, record_limit, selected_date)
            logging.info(f"Query result: {result}")

            # Convert the results to a list
            metrics = []
            for table in result:
                for record in table.records:
                    metrics.append(record.values)

            if not metrics:
                logging.info("No metrics found")
                return jsonify({"status": "success", "metrics": [], "message": "No metrics found"}), 200

            # Return the metrics as a JSON response
            logging.info(f"Returning metrics: {metrics}")
            return jsonify({"status": "success", "metrics": metrics})

        except Exception as e:
            # Log the error for debugging
            logging.error(f"Error occurred: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500



    @app.route('/delete_metric', methods=['POST'])
    def delete_metric():
        try:
            # Create an instance of the InfluxDB v2 connection class
            influx_connection = InfluxDBConnectionV2()
            # Retrieve JSON data from the request
            data = request.get_json()
            if not data:
                return jsonify({"status": "error", "message": "No data provided"}), 400

            host = data.get('host')
            time = data.get('time')
            field = data.get('field')

            if not host or not time or not field:
                return jsonify({"status": "error", "message": "Invalid data provided"}), 400

            # Delete the metric from InfluxDB
            success = influx_connection.delete_metric(host, time, field)

            if success:
                return jsonify({"status": "success"})
            else:
                return jsonify({"status": "error", "message": "Failed to delete the metric"}), 500

        except Exception as e:
            logging.error(f"Error occurred: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500


    # Endpoint to monitor GPU metrics
    @app.route('/gpu_metrics', methods=['GET'])
    def gpu_metrics():
        initialize_nvidia_smi()
        try:
            device_count = nvidia_smi.nvmlDeviceGetCount()
            gpus = []

            for i in range(device_count):
                handle = nvidia_smi.nvmlDeviceGetHandleByIndex(i)
                name = nvidia_smi.nvmlDeviceGetName(handle)
                mem_info = nvidia_smi.nvmlDeviceGetMemoryInfo(handle)
                utilization = nvidia_smi.nvmlDeviceGetUtilizationRates(handle)
                temp = nvidia_smi.nvmlDeviceGetTemperature(handle, nvidia_smi.NVML_TEMPERATURE_GPU)

                gpus.append({
                    'index': i,
                    'name': name.decode('utf-8'),
                    'memory_total': mem_info.total / 1024 ** 2,  # Convert bytes to MB
                    'memory_used': mem_info.used / 1024 ** 2,
                    'memory_free': mem_info.free / 1024 ** 2,
                    'utilization_gpu': utilization.gpu,
                    'utilization_memory': utilization.memory,
                    'temperature': temp
                })

            return jsonify(gpus)
        finally:
            shutdown_nvidia_smi()

    @app.route('/startAllSystemTelemetry/<system_id>', methods=['POST'])
    def start_all_system_telemetry(system_id):
        try:
            influx_connection = InfluxDBConnectionV2()
            # Retrieve GPU system details based on the system_id from your database or data source
            gpu_system = influx_connection.get_gpu_system_by_id(system_id)
            if not gpu_system:
                return jsonify({"status": "error", "message": "GPU system not found"}), 404

            REMOTE_HOST = gpu_system['node_ip']
            USERNAME = gpu_system['user']
            PASSWORD = gpu_system['password']

            influx_connection = InfluxDBConnectionV2()
            influx_connection.server_telemetry(REMOTE_HOST, USERNAME, PASSWORD)

            return jsonify({"status": "success"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500


    """@app.route('/check_connectivity', methods=['POST'])
    def check_connectivity():
        data = request.form
        host = data.get('host')
        username = data.get('username', 'root')
        password = data.get('password', 'Embe1mpls')
        port = int(data.get('port', 830))

        if not host:
            return jsonify({'error': 'Host is required'}), 400

        is_connected = check_juniper_connectivity(host, port, username, password)
        return jsonify({'host': host, 'connected': is_connected})"""

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

        # Loop through each row in the CSV
        for row in csv_reader:
            # Dynamically generate a dictionary for each row using the CSV headers
            row_dict = {key: value for key, value in row.items()}
            topology_list.append(row_dict)

        return jsonify({'topology': topology_list})


    ## Device Health/SSH Test ##

    @app.route('/initiate_ssh', methods=['POST'])
    @login_required
    def initiate_ssh():
        data = request.get_json()
        device_id = data.get('device_id')
        device_info = get_router_details_from_db(device_id)
        if device_info:
            try:
                ws_url = f"ws://localhost:8765/{device_id}"
                return jsonify({'success': True, 'ssh_url': ws_url})
            except Exception as e:
                logging.info(f"initiate_ssh: Ssh Connection Error..!")
                return jsonify({'success': False, 'error': 'Device not found'}), 404
        else:
            return jsonify({'success': False, 'error': 'Device not found'}), 404



    # Flask route to check device and link health

    @app.route('/check_device_health', methods=['POST'])
    @login_required
    def check_health_route():
        data = request.get_json()
        devices = data.get('devices', [])
        edges = data.get('edges', [])
        router_details = get_router_details_from_db()
        # Determine the format of the device data
        use_hostname_as_label = all('hostname' in device for device in devices)
        device_health_status = check_device_health(router_details, devices, use_hostname_as_label)
        link_health_status = check_link_health(router_details, edges)
        health_status = {**device_health_status, **link_health_status}
        logging.info(f"check_health_route:health_status: {health_status}")
        return jsonify({'health_status': health_status})

    # END

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
        try:
            if 'UPLOAD_FOLDER' not in current_app.config:
                flash('Please login again', 'error')
                return redirect(url_for('index'))

            data = request.json
            logging.info('Received data: %s', data)

            if not data or 'imageName' not in data or 'deviceIds' not in data:
                logging.error('Missing image name or device IDs')
                return jsonify(success=False, error="Missing image name or device ID"), 400

            image_name = data['imageName']
            device_ids = data['deviceIds']
            action = data['action']
            image_path = os.path.join(current_app.config['UPLOAD_FOLDER'], image_name)

            logging.info('install_image func Action: %s', action)
            logging.info('install_image func Image Name: %s', image_name)
            logging.info('install_image func Device IDs: %s', device_ids)

            if not image_name:
                logging.error('Image name is missing')
                return jsonify(success=False, error="Missing image name"), 400
            if not device_ids or not isinstance(device_ids, list) or not all(device_ids):
                logging.error('Invalid device IDs')
                return jsonify(success=False, error="Invalid device IDs"), 400
            if not os.path.exists(image_path):
                logging.error('Image file not found')
                return jsonify(success=False, error="Image file not found"), 404

            image_size = os.path.getsize(image_path)
            lock = threading.Lock()
            stop_events = {}
            status = []
            Installerrors = []
            onboard_device_instance = OnboardDeviceClass(socketio, stop_events, Installerrors, None)
            logging.info('Performing Install operation on devices.')
            threads = []
            app_context = current_app._get_current_object()

            # Progress for SCP
            def scp_progress(filename, size, sent, device_id):
                progress = int((sent / size) * 100)
                socketio.emit('install_progress', {
                    'device_id': device_id,
                    'progress': progress,
                    'stage': 'copying'
                })
                #logging.info(f"Copying progress for {device_id}: {progress}%")

            # Installation progress handler
            def myprogress(report,device_id):
                """
                Progress handler for the image installation process.
                """
                logging.info(f"Installation progress on {device_id}: {report}")
                socketio.emit('install_progress', {
                    'device_id': device_id,
                    'progress': report,
                    'stage': 'installing'
                })


            '''def install_image_on_device(dev, remote_image_path, device_id):
                try:
                    sw = SW(dev)
                    logging.info(f"Starting installation on device {device_id} with image {remote_image_path}")

                    # Emit that installation is starting with a valid device_id
                    if not device_id:
                        logging.error("device_id is missing or undefined")
                        return False

                    socketio.emit('install_progress', {
                        'device_id': device_id,
                        'progress': 10,
                        'stage': 'installing',
                        'message': 'Starting installation'  # Always include a message
                    })

                    # Get current software version from the device
                    device_version_info = dev.rpc.get_software_information()
                    device_version = device_version_info.xpath('//software-information/junos-version')

                    if not device_version:
                        logging.error(f"Could not retrieve version for device {device_id}")
                        socketio.emit('install_progress', {
                            'device_id': device_id,
                            'progress': 0,
                            'stage': 'error',
                            'message': f"Failed to retrieve version for {device_id}"  # Include a message here
                        })
                        return False

                    device_version_name = device_version[0].text.split('-')[-2]
                    logging.info(f"Current software version on {device_id}: {device_version_name}")
                    image_install_version = remote_image_path.split('-')[-2]
                    logging.info(f"Image version to install on {device_id}: {image_install_version}")

                    # Check if the version to install matches the current version
                    if image_install_version == device_version_name:
                        message = f"Device {device_id} is already running version {image_install_version}. Skipping installation."
                        logging.info(message)
                        #errors.append("DupVersion")
                        socketio.emit('install_progress', {
                            'device_id': device_id,
                            'progress': 100,
                            'stage': 'DupVersion',  # Duplicate version stage
                            'message': "DupVersion,skiping.!"  # Pass the message argument here
                        })
                        return False

                    # Check if a pending upgrade exists
                    upgrade_status = dev.rpc.get_software_information()
                    if "upgrade_in_progress" in upgrade_status.xpath('//software-information'):
                        error_message = "There is a pending upgrade. Please reboot the device to complete the installation or rollback."
                        logging.error(error_message)
                        socketio.emit('install_progress', {
                            'device_id': device_id,
                            'progress': 0,
                            'stage': 'error',
                            'message': error_message  # Always pass a message
                        })
                        return False

                    # Proceed with the installation
                    ok, msg = sw.install(package=remote_image_path, validate=True, progress=myprogress,
                                         checksum_timeout=400, no_copy=True)

                    if ok:
                        # Emit install complete, then emit reboot stage
                        socketio.emit('install_progress', {
                            'device_id': device_id,
                            'progress': 100,
                            'stage': 'install_complete',
                            'message': 'Installation complete'  # Include a success message
                        })
                        logging.info(f"Image installed successfully on {device_id}")
                        socketio.emit('install_progress', {
                            'device_id': device_id,
                            'progress': 100,
                            'stage': 'rebooting',
                            'message': 'Rebooting device'  # Provide a reboot message
                        })
                        sw.reboot()
                        return True
                    else:
                        # Handle errors during installation
                        if "Another package installation in progress" in msg:
                            logging.error(f"Another package installation is already in progress on {device_id}.")
                            socketio.emit('install_progress', {
                                'device_id': device_id,
                                'progress': 0,
                                'stage': 'error',
                                'message': 'Another installation is already in progress.'  # Include error message
                            })
                        else:
                            logging.error(f'Failed to install image on {device_id}: {msg}')
                        return False
                except Exception as e:
                    logging.error(f"Error installing image on {device_id}: {str(e)}")
                    socketio.emit('install_progress', {
                        'device_id': device_id,
                        'progress': 0,
                        'stage': 'error',
                        'message': f"Install Error: {str(e)}"  # Include the exception in the message
                    })
                    return False'''
            '''def install_image_on_device(dev, remote_image_path, device_id):
                try:
                    sw = SW(dev)
                    logging.info(f"Starting installation on device {device_id} with image {remote_image_path}")

                    # Emit that installation is starting with a valid device_id
                    if not device_id:
                        logging.error("device_id is missing or undefined")
                        return False

                    socketio.emit('install_progress', {
                        'device_id': device_id,
                        'progress': 10,
                        'stage': 'installing',
                        'message': 'Starting installation'  # Always include a message
                    })

                    # Get current software version from the device
                    device_version_info = dev.rpc.get_software_information()
                    device_version = device_version_info.xpath('//software-information/junos-version')

                    if not device_version:
                        logging.error(f"Could not retrieve version for device {device_id}")
                        socketio.emit('install_progress', {
                            'device_id': device_id,
                            'progress': 0,
                            'stage': 'error',
                            'message': f"Failed to retrieve version for {device_id}"  # Include a message here
                        })
                        return False

                    device_version_name = device_version[0].text.split('-')[-2]
                    logging.info(f"Current software version on {device_id}: {device_version_name}")
                    image_install_version = remote_image_path.split('-')[-2]
                    logging.info(f"Image version to install on {device_id}: {image_install_version}")

                    # Check if the version to install matches the current version
                    if image_install_version == device_version_name:
                        message = f"Device {device_id} is already running version {image_install_version}. Skipping installation."
                        logging.info(message)
                        socketio.emit('install_progress', {
                            'device_id': device_id,
                            'progress': 100,
                            'stage': 'DupVersion',  # Duplicate version stage
                            'message': "DupVersion, skipping.!"  # Pass the message argument here
                        })
                        return False

                    # Check if a pending upgrade exists
                    upgrade_status = dev.rpc.get_software_information()
                    if "upgrade_in_progress" in upgrade_status.xpath('//software-information'):
                        error_message = "There is a pending upgrade. Please reboot the device to complete the installation or rollback."
                        logging.error(error_message)
                        socketio.emit('install_progress', {
                            'device_id': device_id,
                            'progress': 0,
                            'stage': 'error',
                            'message': error_message  # Always pass a message
                        })
                        return False

                    # Proceed with the installation
                    ok, msg = sw.install(package=remote_image_path, validate=True, progress=myprogress,
                                         checksum_timeout=400, no_copy=True)

                    if ok:
                        # Emit install complete, then emit reboot stage
                        socketio.emit('install_progress', {
                            'device_id': device_id,
                            'progress': 100,
                            'stage': 'install_complete',
                            'message': 'Installation complete'  # Include a success message
                        })
                        logging.info(f"Image installed successfully on {device_id}")
                        socketio.emit('install_progress', {
                            'device_id': device_id,
                            'progress': 100,
                            'stage': 'rebooting',
                            'message': 'Rebooting device'  # Provide a reboot message
                        })
                        sw.reboot()

                        # Wait for the device to come back online
                        time.sleep(60)  # Wait for 60 seconds (this can be adjusted based on typical reboot times)

                        for attempt in range(12):  # Try for 12 iterations (about 10-12 minutes)
                            try:
                                dev.open()  # Re-establish the connection
                                logging.info(f"Device {device_id} is back online after reboot.")
                                socketio.emit('install_progress', {
                                    'device_id': device_id,
                                    'progress': 90,
                                    'stage': 'device_online',
                                    'message': 'Device online'
                                })

                                # Check if the installed version matches the target version
                                device_version_info = dev.rpc.get_software_information()
                                device_version = device_version_info.xpath('//software-information/junos-version')
                                if device_version and device_version[0].text.split('-')[-2] == image_install_version:
                                    logging.info(f"Version verification successful for device {device_id}.")
                                    socketio.emit('install_progress', {
                                        'device_id': device_id,
                                        'progress': 100,
                                        'stage': 'version_check',
                                        'message': 'Success!.'
                                    })
                                    return True
                                else:
                                    logging.error(f"Version mismatch after reboot on device {device_id}.")
                                    socketio.emit('install_progress', {
                                        'device_id': device_id,
                                        'progress': 0,
                                        'stage': 'error',
                                        'message': 'Version mismatch after reboot.'
                                    })
                                    return False
                            except ConnectError:
                                logging.warning(
                                    f"Device {device_id} is not reachable. Retrying... Attempt {attempt + 1}")
                                time.sleep(30)  # Wait for 30 seconds before retrying
                        # If the device is not reachable after 12 attempts, emit error
                        logging.error(f"Device {device_id} did not come back online after reboot.")
                        socketio.emit('install_progress', {
                            'device_id': device_id,
                            'progress': 0,
                            'stage': 'error',
                            'message': f"Device {device_id} did not come back online after reboot."
                        })
                        return False
                    else:
                        # Handle errors during installation
                        if "Another package installation in progress" in msg:
                            logging.error(f"Another package installation is already in progress on {device_id}.")
                            socketio.emit('install_progress', {
                                'device_id': device_id,
                                'progress': 0,
                                'stage': 'error',
                                'message': 'Another installation is already in progress.'  # Include error message
                            })
                        else:
                            logging.error(f'Failed to install image on {device_id}: {msg}')
                            socketio.emit('install_progress', {
                                'device_id': device_id,
                                'progress': 0,
                                'stage': 'error',
                                'message': "Install Failed."  # Provide a failure message
                            })
                        return False
                except Exception as e:
                    logging.error(f"Error installing image on {device_id}: {str(e)}")
                    socketio.emit('install_progress', {
                        'device_id': device_id,
                        'progress': 0,
                        'stage': 'error',
                        'message': f"Install Error: {str(e)}"  # Include the exception in the message
                    })
                    return False'''

            '''def reboot_and_check(dev, device_id):
                """Helper function to reboot the device and verify if the device comes back online."""
                sw.reboot()
                # Wait for the device to come back online
                time.sleep(60)  # Adjust based on typical reboot times
                for attempt in range(12):  # Try for 12 iterations (about 10-12 minutes)
                    try:
                        dev.open(timeout=120)  # Re-establish the connection with increased timeout
                        logging.info(f"Device {device_id} is back online after reboot.")
                        if dev.connected:
                            socketio.emit('install_progress', {
                                'device_id': device_id,
                                'progress': 90,
                                'stage': 'device_online',
                                'message': 'Device online'
                            })
                            return True
                    except ConnectError as e:
                        logging.warning(
                            f"SSH connection failed for device {device_id}. Retrying... Attempt {attempt + 1}: {e}")
                        time.sleep(60)  # Wait for 60 seconds before retrying
                    except Exception as e:
                        logging.warning(f"SSH timeout for device {device_id}. Retrying... Attempt {attempt + 1}: {e}")
                        socketio.emit('install_progress', {
                            'device_id': device_id,
                            'stage': 'message',
                            'message': f'Connect Retry{attempt + 1}'
                        })
                        time.sleep(60)  # Wait for 60 seconds before retrying

                # If the device is not reachable after 12 attempts, emit an error
                logging.error(f"Device {device_id} did not come back online after reboot.")
                socketio.emit('install_progress', {
                    'device_id': device_id,
                    'progress': 0,
                    'stage': 'error',
                    'message': f"Device {device_id} did not come back online after reboot."
                })
                return False'''

            def check_versions_and_rollback(dev, package_name, device_id, sw):

                def reboot_and_check(dev, device_id):
                    """Helper function to reboot the device and verify if the device comes back online."""
                    sw.reboot()
                    # Wait for the device to come back online
                    time.sleep(60)  # Adjust based on typical reboot times
                    for attempt in range(12):  # Try for 12 iterations (about 10-12 minutes)
                        try:
                            dev.open(timeout=120)  # Re-establish the connection with increased timeout
                            logging.info(f"Device {device_id} is back online after reboot.")
                            if dev.connected:
                                socketio.emit('install_progress', {
                                    'device_id': device_id,
                                    'progress': 90,
                                    'stage': 'device_online',
                                    'message': 'Device online'
                                })
                                return True
                        except ConnectError as e:
                            logging.warning(
                                f"SSH connection failed for device {device_id}. Retrying... Attempt {attempt + 1}: {e}")
                            time.sleep(60)  # Wait for 60 seconds before retrying
                        except Exception as e:
                            logging.warning(f"SSH timeout for device {device_id}. Retrying... Attempt {attempt + 1}: {e}")
                            socketio.emit('install_progress', {
                                'device_id': device_id,
                                'stage': 'message',
                                'message': f'Connect Retry{attempt + 1}'
                            })
                            time.sleep(60)  # Wait for 60 seconds before retrying

                    # If the device is not reachable after 12 attempts, emit an error
                    logging.error(f"Device {device_id} did not come back online after reboot.")
                    socketio.emit('install_progress', {
                        'device_id': device_id,
                        'progress': 0,
                        'stage': 'error',
                        'message': f"Device {device_id} did not come back online after reboot."
                    })
                    return False

                try:
                    # Fetch system software list XML output using CLI
                    software_info_xml = dev.cli("show system software list | display xml", format='xml')
                    # Extract relevant versions
                    current_version = software_info_xml.xpath('//version-list/current-version')[0].text
                    rollback_version = software_info_xml.xpath('//version-list/rollback-version')[
                        0].text if software_info_xml.xpath('//version-list/rollback-version') else None
                    nextboot_version = software_info_xml.xpath('//version-list/nextboot-version')[
                        0].text if software_info_xml.xpath('//version-list/nextboot-version') else None
                    other_versions_list = [v.text for v in software_info_xml.xpath('//other-versions')]
                    package_name = os.path.basename(package_name).replace(".iso", "")

                    logging.info(
                        f"Checking Available Rollback.!: Device {device_id} - Package name: {package_name}, Current version: {current_version}, Rollback version: {rollback_version}, Nextboot version: {nextboot_version}, Other versions: {other_versions_list}")

                    # Case 1: If current version matches package_name
                    if current_version == package_name:
                        logging.info(f"Device {device_id} is now running version {current_version}.")
                        socketio.emit('install_progress', {
                            'device_id': device_id,
                            'progress': 100,
                            'stage': 'version_check',
                            'message': f'Version Match.!'
                        })
                        return True
                    # Case 2: If nextboot_version is set but doesn't match package_name
                    if nextboot_version:
                        logging.info(
                            f"Nextboot version {nextboot_version} is set. Rebooting device to check other versions.")
                        socketio.emit('install_progress', {
                            'device_id': device_id,
                            'progress': 100,
                            'stage': 'rebooting',
                            'message': f"Rebooting device {device_id} with nextboot version {nextboot_version}"
                        })

                        reboot_success = reboot_and_check(dev, device_id)
                        if reboot_success:
                            # After reboot, check if the current version matches the package name
                            logging.info(
                                f"Device {device_id} reboot Success.!.")
                            #device_version_info = dev.rpc.get_software_information()
                            if current_version == package_name:
                                logging.info(
                                    f"Device {device_id} is now running version {package_name}.")
                                socketio.emit('install_progress', {
                                    'device_id': device_id,
                                    'progress': 100,
                                    'stage': 'version_check',
                                    'message': f'Success! Version {package_name} verified after reboot.'
                                })
                                return True

                    # Case 3: If package_name is in other_versions_list or rollback version
                    if package_name in other_versions_list or package_name == rollback_version:
                        logging.info(f"Package {package_name} is available. Performing rollback.")
                        max_retries = 3  # Maximum number of retry attempts
                        retry_attempts = 0
                        rpc_command = None

                        while retry_attempts < max_retries:
                            try:
                                # Try initiating the rollback
                                socketio.emit('install_progress', {
                                    'device_id': device_id,
                                    'progress': 20,
                                    'stage': 'version_check',
                                    'message': f'Checking Rollback'
                                })
                                rpc_command = dev.rpc.request_package_rollback(package_name=package_name)
                                if rpc_command is not None:
                                    logging.info(
                                        f"Rollback of {package_name} initiated successfully on {device_id}")
                                    socketio.emit('install_progress', {
                                        'device_id': device_id,
                                        'progress': 80,
                                        'stage': 'version_check',
                                        'message': f'rollback complete'
                                    })
                                    time.sleep(10)
                                    socketio.emit('install_progress', {
                                        'device_id': device_id,
                                        'progress': 90,
                                        'stage': 'rebooting'

                                    })
                                    reboot_success = reboot_and_check(dev, device_id)
                                    if reboot_success:
                                        socketio.emit('install_progress', {
                                            'device_id': device_id,
                                            'progress': 100,
                                            'stage': 'install_complete'

                                        })
                                        return True  # Exit loop if rollback succeeds
                            except Exception as err:
                                logging.error(
                                    f"Package {package_name} rollback failed on attempt {retry_attempts + 1}. Error: {err}")
                                retry_attempts += 1
                                socketio.emit('install_progress', {
                                    'device_id': device_id,
                                    'progress': 100,
                                    'stage': 'version_check',
                                    'message': f'rollback retry{retry_attempts}'
                                })
                                time.sleep(60)  # Wait 60 seconds before retrying
                            if retry_attempts == max_retries:
                                logging.error(
                                    f"Package {package_name} rollback failed after {max_retries} attempts.")
                                socketio.emit('install_progress', {
                                    'device_id': device_id,
                                    'progress': 0,
                                    'stage': 'error',
                                    'message': f"rollback failed."
                                })
                                return False
                        if rpc_command is not None:
                            logging.info(f"Received rolback RPC of {package_name}  on {device_id}, starting Reboot.")
                            socketio.emit('install_progress', {
                                'device_id': device_id,
                                'progress': 100,
                                'stage': 'version_check',
                                'message': f'Rollback Done.!'
                            })
                            reboot_success = reboot_and_check(dev, device_id)
                            if reboot_success:
                                socketio.emit('install_progress', {
                                    'device_id': device_id,
                                    'progress': 100,
                                    'stage': 'version_check',
                                    'message': f'Device Online.!'
                                })
                                # After reboot, verify the current version
                                #device_version_info = dev.rpc.get_software_information()
                                if current_version == package_name:
                                    logging.info(
                                        f"Device {device_id} is now running version {current_version}.")
                                    socketio.emit('install_progress', {
                                        'device_id': device_id,
                                        'progress': 100,
                                        'stage': 'version_check',
                                        'message': f'Success! Version {package_name} verified after rollback and reboot.'
                                    })
                                    return True
                        else:
                            logging.error(f"Failed to initiate rollback of {package_name} on {device_id}.")
                            socketio.emit('install_progress', {
                                'device_id': device_id,
                                'progress': 0,
                                'stage': 'error',
                                'message': f"Failed to initiate rollback of {package_name}"
                            })
                            return False

                    # If no conditions are met, return False to proceed with installation
                    logging.info(
                        f"No matching Rollback version found for {package_name}. {device_id}.")
                    return False

                except Exception as e:
                    logging.error(f"Error checking versions or performing rollback on {device_id}: {str(e)}")
                    socketio.emit('install_progress', {
                        'device_id': device_id,
                        'progress': 0,
                        'stage': 'error',
                        'message': f"Error checking versions: {str(e)}"
                    })
                    return False

            def install_image_on_device(dev, remote_image_path, device_id):
                sw = SW(dev)
                try:
                    logging.info(f"Starting installation on device {device_id} with image {remote_image_path}")

                    if not device_id:
                        logging.error("device_id is missing or undefined")
                        return False

                    logging.info(
                        f"Checking if rollback is needed for device {device_id} before proceeding with installation.")
                    rollback_handled = check_versions_and_rollback(dev, remote_image_path, device_id, sw)

                    if rollback_handled:
                        logging.info(
                            f"Rollback handled the software installation on device {device_id}, skipping install.")
                        return True

                    socketio.emit('install_progress', {
                        'device_id': device_id,
                        'progress': 10,
                        'stage': 'installing',
                        'message': 'Starting installation'
                    })

                    logging.info(
                        f"No Rollback to Perform, Starting SW installation on device {device_id} with image {remote_image_path}")
                    try:
                        ok, msg = sw.install(package=remote_image_path, validate=True,timeout=60,no_copy=True)
                        logging.error(f'Failed to install image on {device_id}: {msg}')
                        if ok:
                            socketio.emit('install_progress', {
                                'device_id': device_id,
                                'progress': 100,
                                'stage': 'install_complete',
                                'message': 'Installation complete'
                            })
                            logging.info(f"Image installed successfully on {device_id}")
                            socketio.emit('install_progress', {
                                'device_id': device_id,
                                'progress': 100,
                                'stage': 'rebooting',
                                'message': 'Rebooting device'
                            })
                            return reboot_and_check(dev, device_id)
                        else:
                            logging.error(f'Failed to install image on {device_id}: {msg}')
                            socketio.emit('install_progress', {
                                'device_id': device_id,
                                'progress': 0,
                                'stage': 'error',
                                'message': "Install Failed."
                            })
                            return False
                    except Exception as err:
                        #logging.error(f'Failed to install image on {device_id}: {msg}')
                        logging.error(f"install_image_on_device, Install Error: {err}")
                        socketio.emit('install_progress', {
                            'device_id': device_id,
                            'progress': 0,
                            'stage': 'error',
                            'message': 'fail..trying again'
                        })
                        logging.info(f"All Install Failed, fallback to cli install : {device_id}: {err}")
                        install_cmd = f"request system software add {remote_image_path} no-validate"
                        logging.info(f"Executing installation command on {device_id}: {install_cmd}")
                        try:
                            install_response = dev.cli(install_cmd)
                            logging.info(f"Install Response for {device_id}: {install_response}")
                        except RpcTimeoutError as err:
                            logging.info(f"RpcTimeoutError during cli install: {device_id}: {err}")
                            socketio.emit('install_progress', {
                                'device_id': device_id,
                                'stage': 'message',
                                'message': 'Waiting'
                            })
                            time.sleep(60)
                            for attempt in range(5):
                                rollback_handled = check_versions_and_rollback(dev, remote_image_path, device_id, sw)
                                logging.info(f"rollback_handled complete: {device_id}: {rollback_handled}")
                                if rollback_handled:
                                    return True
                                time.sleep(60)
                        except Exception as err:
                            logging.info(f"Install Response Error: {device_id}: {err}")
                except Exception as e:
                    logging.error(f"Error installing image on {device_id}: {str(e)}")
                    socketio.emit('install_progress', {
                        'device_id': device_id,
                        'progress': 0,
                        'stage': 'error',
                        'message': f"Install Error: {str(e)}"
                    })
                    return False

            def copy_image_to_device(device, image_path, image_size, device_id, action, app_context, device_connection,
                                     status):
                with app_context.app_context():
                    try:
                        logging.info(f"Checking for existing image on device: {device_id}")
                        try:
                            dev = device_connection
                            # Check available storage space on the device
                            storage_ok, avail_space, mount_point = onboard_device_instance.check_storage_space(dev,
                                                                                                               image_size)
                            if not storage_ok:
                                error_message = f"Insufficient storage space on {device_id}. Required: {image_size} bytes, Available: {avail_space} bytes"
                                logging.error(error_message)
                                socketio.emit('install_progress', {
                                    'device_id': device_id, 'progress': 0, 'stage': 'error', 'message': error_message
                                })
                                Installerrors.append(error_message)
                                return

                            # Set the remote image path to /var/tmp
                            remote_image_path = f"/var/tmp/{os.path.basename(image_path)}"
                            logging.info(f"Remote image path set to: {remote_image_path}")

                            # Check if the image already exists on the device
                            local_image_md5 = onboard_device_instance.calculate_md5(image_path)
                            remote_md5 = onboard_device_instance.get_remote_md5(dev, remote_image_path, local_image_md5)

                            if remote_md5 is True:
                                message = f"Image already exists on {device_id} with matching MD5 checksum."
                                logging.info(message)
                                socketio.emit('install_progress', {
                                    'device_id': device_id, 'stage': 'exists', 'progress': 100, 'message': "Already Exists.!"
                                })
                                thread_safe_append(status, 200)
                            else:
                                thread_safe_append(status, 201)
                                logging.info(
                                    f"No existing image found or MD5 mismatch on {device.hostname}. Proceeding with copy.")

                                # Perform the image copy with progress emission
                                for attempt in range(3):
                                    try:
                                        with SCP(dev, progress=lambda f, s, t: scp_progress(f, s, t, device_id)) as scp:
                                            scp.put(image_path, remote_path=remote_image_path)

                                        logging.info(
                                            f'Image copied to {device.hostname}: {remote_image_path} successfully.')
                                        socketio.emit('install_progress', {
                                            'device_id': device_id, 'progress': 100, 'stage': 'copycomplete',
                                            'message': 'Copying complete'
                                        })
                                        thread_safe_append(status,
                                                           f"Image copied to {device_id}:{remote_image_path} successfully.")
                                        break
                                    except Exception as e:
                                        logging.error(f'Error copying image on attempt {attempt + 1}: {str(e)}')
                                        if attempt == 2:
                                            socketio.emit('install_progress', {
                                                'device_id': device_id, 'progress': 0, 'stage': 'error',
                                                'message': str(e)
                                            })
                                            Installerrors.append(
                                                f"Error copying image to {device_id} after 3 attempts: {str(e)}")
                                            return

                            # Emit "Installing" message only if action is 'installSelectedImageBtn'
                            if action == 'installSelectedImageBtn':
                                socketio.emit('install_progress', {
                                    'device_id': device_id, 'progress': 0, 'stage': 'installing',
                                    'message': 'Starting installation'
                                })
                                thread_safe_append(status, 202)

                                # Proceed with installation
                                for attempt in range(3):
                                    try:
                                        install_status = install_image_on_device(dev, remote_image_path, device_id)
                                        if install_status:
                                            thread_safe_append(status, f"Image installed on {device_id} successfully.")
                                        else:
                                            Installerrors.append(f"Install Fail.!.")
                                        break
                                    except Exception as e:
                                        logging.error(f'Error Installing image on attempt {attempt + 1}: {str(e)}')
                                        if attempt == 2:
                                            socketio.emit('install_progress', {
                                                'device_id': device_id, 'progress': 0, 'stage': 'error',
                                                'message': str(e)
                                            })
                                            Installerrors.append(
                                                f"Error Installing image to {device_id} after 3 attempts: {str(e)}")
                                            return
                        except Exception as e:
                            logging.error(f"Error connecting to device {device_id}: {str(e)}")
                            Installerrors.append(f"Error connecting to device {device_id}: {str(e)}")
                            socketio.emit('install_progress', {
                                'device_id': device_id, 'progress': 0, 'stage': 'error', 'message': str(e)
                            })
                    except Exception as e:
                        logging.error(f"Unexpected error during the image copy process: {str(e)}")
                        Installerrors.append(f"Unexpected error during the image copy process: {str(e)}")
                        socketio.emit('install_progress', {
                            'device_id': device_id, 'progress': 0, 'stage': 'error', 'message': str(e)
                        })


            def thread_safe_append(lst, item):
                with lock:
                    lst.append(item)

            for device_id in device_ids:
                device = db.session.query(DeviceInfo).filter_by(hostname=device_id).first()
                if not device:
                    thread_safe_append(Installerrors, f"Device ID {device_id} not found")
                    continue
                device_connector = DeviceConnectorClass(device.hostname, device.ip, device.username, device.password)
                try:
                    device_connection = device_connector.connect_to_device()
                except Exception as e:
                    thread_safe_append(Installerrors, f"Failed to connect to device {device_id}: {str(e)}")
                    continue

                stop_events[device_id] = threading.Event()
                logging.info(f"*********** {device_connection}")
                thread = threading.Thread(target=copy_image_to_device, args=(
                    device, image_path, image_size, device_id, action, app_context, device_connection, status))
                thread.start()
                threads.append(thread)

            for thread in threads:
                thread.join()

            if status:
                logging.info(f"Returning status: {status}, errors: {Installerrors}")
                return jsonify(success=True, status=status, errors=Installerrors)
            else:
                logging.info(f"Returning errors: {Installerrors}")
                return jsonify(success=False, status=status, errors=Installerrors)
        except Exception as errors:
            logging.error(f"Unexpected error in install_image route: {str(errors)}")
            return jsonify(success=False, error=str(errors)), 500


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
            images = [f for f in files if
                      os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], f)) and 'install' in f.lower()]
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
        #print(upload_folder)
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

    @app.route('/fetch_device_config/<string:hostname>', methods=['GET'])
    @login_required
    def fetch_device_config(hostname):
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash('Please login again', 'error')
            return jsonify({'success': False, 'error': 'Please login again'}), 401

        # Find the device by hostname
        device = db.session.query(DeviceInfo).filter_by(hostname=hostname).first()
        if not device:
            logging.error("Device not found")
            return jsonify({"success": False, "message": "Device not found"}), 404

        try:
            # Emit progress: Starting connection process
            socketio.emit('progress', {
                'device': device.hostname,
                'progress': 25,
                'stage': 'Connecting to device'
            })

            # Connect to the device
            with Device(host=device.ip, user=device.username, passwd=device.password, port=22) as dev:
                socketio.emit('progress', {
                    'device': device.hostname,
                    'progress': 50,
                    'stage': 'Fetching configuration'
                })

                # Fetch configuration from the device
                config = dev.rpc.get_config(options={'format': 'set'})
                socketio.emit('progress', {
                    'device': device.hostname,
                    'progress': 75,
                    'stage': 'Processing configuration'
                })

        except ConnectAuthError as e:
            logging.error(f"Connection authentication error for device {device.hostname}: {str(e)}")
            socketio.emit('progress', {
                'device': device.hostname,
                'progress': 0,
                'stage': 'Error',
                'error': f"Authentication error: {str(e)}"
            })
            return jsonify({"success": False, "message": f"Connection authentication error: {str(e)}"}), 500

        except ConnectError as e:
            logging.error(f"Connection error for device {device.hostname}: {str(e)}")
            socketio.emit('progress', {
                'device': device.hostname,
                'progress': 0,
                'stage': 'Error',
                'error': f"Connection error: {str(e)}"
            })
            return jsonify({"success": False, "message": f"Connection error: {str(e)}"}), 500

        except Exception as e:
            logging.error(f"Error fetching configuration for device {device.hostname}: {str(e)}")
            socketio.emit('progress', {
                'device': device.hostname,
                'progress': 0,
                'stage': 'Error',
                'error': f"Error fetching configuration: {str(e)}"
            })
            return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

        # Emit progress: Configuration fetched successfully
        socketio.emit('progress', {
            'device': device.hostname,
            'progress': 100,
            'stage': 'Completed'
        })

        # Prepare the configuration data
        config_data = {
            "success": True,
            "hostname": device.hostname,
            "config": config.text
        }

        logging.info(f"Configuration fetched successfully for device {device.hostname}")
        return jsonify(config_data)

    '''@app.route('/fetch_device_config/<string:hostname>', methods=['GET'])
    @login_required
    def fetch_device_config(hostname):
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash('Please login again', 'error')
            return jsonify({'success': False, 'error': 'Please login again'}), 401

        device = db.session.query(DeviceInfo).filter_by(
            hostname=hostname).first()  # Fetch by hostname instead of device_id
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
        return jsonify(config_data)'''



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
        config_format = "set"
        result = transfer_file_to_router(config_lines, router_ip, router_user, router_password, device_name,
                                         config_format)

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
        #device_id = data.get('id')
        hostname = data.get('hostname')
        new_username = data.get('username')
        new_password = data.get('password')
        device = db.session.query(DeviceInfo).filter_by(hostname=hostname).first()
        #device = db.session.get(DeviceInfo, device_id)
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

    @app.route('/restore_device_config/<string:hostname>', methods=['POST'])
    @login_required
    def restore_device_config_view(hostname):
        # Ensure UPLOAD_FOLDER is in config
        if 'UPLOAD_FOLDER' not in current_app.config:
            return jsonify(success=False, error='Please login again'), 401

        # Find the device by hostname
        device = db.session.query(DeviceInfo).filter_by(hostname=hostname).first()
        total_devices = 1  # This is designed for a single device
        completed_devices = 0

        # Check if the device exists
        if not device:
            return jsonify(success=False, error='Device not found'), 404

        # Create the path to the user's config file
        user_folder = os.path.join(current_app.config['DEVICE_CONFIG_FOLDER'], str(current_user.username))
        config_filename = f"{device.hostname}_config.txt"
        config_filepath = os.path.join(user_folder, config_filename)

        # Log the file path for debugging
        logging.info(f"Restoring config from: {config_filepath}")

        # Check if the configuration file exists
        if not os.path.exists(config_filepath):
            return jsonify(success=False, error='Configuration file not found'), 404

        try:
            # Emit progress: Start restoring configuration
            socketio.emit('overall_progress', {
                'device': device.hostname,
                'progress': 25,
                'stage': 'Reading configuration'
            })

            # Open the configuration file and filter out lines starting with "##"
            with open(config_filepath, 'r') as config_file:
                config_lines = config_file.readlines()
                clean_config_lines = [line for line in config_lines if not line.startswith("##")]

                # Determine the format of the configuration
                config_format = 'set' if any(line.startswith('set ') for line in clean_config_lines) else 'text'

            # Emit progress: Preparing to transfer configuration
            socketio.emit('overall_progress', {
                'device': device.hostname,
                'progress': 50,
                'stage': 'Transferring configuration to device'
            })

            # Transfer the configuration to the router
            result = transfer_file_to_router(
                clean_config_lines, device.ip, device.username, device.password, device.hostname, config_format
            )

            if "successfully" in result:
                # Configuration transfer was successful
                completed_devices += 1
                progress = int((completed_devices / total_devices) * 100)
                socketio.emit('overall_progress', {
                    'device': device.hostname,
                    'progress': progress,
                    'stage': 'Completed'
                })
                logging.info(f"Configuration restored successfully for {device.hostname}")
                return jsonify(success=True)

            else:
                # Handle configuration transfer errors
                socketio.emit('overall_progress', {
                    'device': device.hostname,
                    'progress': 0,
                    'stage': 'Error',
                    'error': result
                })
                logging.error(f"Error transferring configuration for {device.hostname}: {result}")
                return jsonify(success=False, error=result)

        except Exception as e:
            # Catch any general exceptions
            logging.error(f"Error restoring configuration for device {hostname}: {str(e)}")
            socketio.emit('overall_progress', {
                'device': device.hostname,
                'progress': 0,
                'stage': 'Error',
                'error': str(e)
            })
            return jsonify(success=False, error=str(e)), 500

    @app.route('/save_device_config', methods=['POST'])
    @login_required
    def save_device_config():
        # Ensure the UPLOAD_FOLDER is correctly set
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash('Please login again', 'error')
            return jsonify({'success': False, 'error': 'Please login again'}), 401

        data = request.get_json()
        device_data = data.get('deviceData')
        config_data = data.get('configData')
        total_devices = 1  # This is designed for a single device but can be extended
        completed_devices = 0

        logging.info(f"Received device data: {device_data}")

        # Validate input data
        if not device_data or not config_data:
            logging.error('Missing device data or configuration data')
            return jsonify({'success': False, 'error': 'Missing device data or configuration data'})

        try:
            # Prepare the user-specific folder and file path
            user_folder = os.path.join(current_app.config['DEVICE_CONFIG_FOLDER'], str(current_user.username))
            os.makedirs(user_folder, exist_ok=True)  # Ensure the directory exists
            config_filename = f"{device_data['hostname']}_config.txt"
            config_filepath = os.path.join(user_folder, config_filename)
            config_content = config_data['config']  # Ensure the correct key is used

            # Emit progress: Starting configuration save
            socketio.emit('overall_progress', {
                'device': device_data['hostname'],
                'progress': 25,
                'stage': 'Saving configuration'
            })

            # Write configuration to the file
            with open(config_filepath, 'w') as config_file:
                config_file.write(config_content)

            # Emit progress: Configuration saved successfully
            completed_devices += 1
            progress = int((completed_devices / total_devices) * 100)
            logging.info(f"Config saved successfully for {device_data['hostname']} at {config_filepath}")

            socketio.emit('overall_progress', {
                'device': device_data['hostname'],
                'progress': progress,
                'stage': 'Completed'
            })

            return jsonify({'success': True})

        except OSError as os_err:
            # Handle file I/O related errors specifically
            logging.error(
                f"File error saving configuration for {device_data.get('hostname', 'unknown')}: {str(os_err)}")
            socketio.emit('overall_progress', {
                'device': device_data['hostname'],
                'progress': 0,
                'stage': 'Error',
                'error': f"File error: {str(os_err)}"
            })
            return jsonify({'success': False, 'error': f"File error: {str(os_err)}"})

        except Exception as e:
            # Catch all other exceptions
            logging.error(f"General error saving configuration for {device_data.get('hostname', 'unknown')}: {str(e)}")
            socketio.emit('overall_progress', {
                'device': device_data['hostname'],
                'progress': 0,
                'stage': 'Error',
                'error': str(e)
            })
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/save_all_device_configs', methods=['POST'])
    @login_required
    def save_all_device_configs():
        # Check if the user is logged in
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'error': 'User is not logged in'}), 401

        # Ensure that the user folder is correctly set after login
        user_folder = os.path.join(current_app.config['DEVICE_CONFIG_FOLDER'], str(current_user.username))
        os.makedirs(user_folder, exist_ok=True)  # Create the folder if it doesn't exist

        # If for some reason the folder is not found in the config, prompt re-login
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash('Please login again to upload files', 'error')
            return jsonify({'success': False, 'error': 'Please login again'}), 401

        # Retrieve the devices associated with the logged-in user
        devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
        total_devices = len(devices)

        if total_devices == 0:
            return jsonify({'success': False, 'error': 'No devices found for this user'}), 400

        errors = []

        # Loop through each device and process configuration saving
        for index, device in enumerate(devices):
            try:
                logging.info(f"Connecting to device {device.hostname} at {device.ip}")

                # Open a connection to the device
                dev = Device(host=device.ip, user=device.username, passwd=device.password, port=22)
                dev.open()
                logging.info(f"Successfully connected to {device.hostname}")

                # Retrieve the configuration in text format
                config = dev.rpc.get_config(options={'format': 'text'}).text
                dev.close()  # Close the connection once the config is retrieved

                # Prepare the filename and path for saving the configuration
                config_filename = f"{device.hostname}_config.txt"
                config_filepath = os.path.join(user_folder, config_filename)

                # Save the configuration to a file
                with open(config_filepath, 'w') as config_file:
                    config_file.write(config)
                logging.info(f"Config written successfully to {config_filepath}")

                # Emit progress update via Socket.IO
                progress = int(((index + 1) / total_devices) * 100)
                socketio.emit('overall_progress', {
                    'device': device.hostname,
                    'progress': progress,
                    'stage': 'Completed'
                })

            except (ConnectAuthError, ConnectError) as e:
                # Handle device connection errors
                logging.error(f"Error connecting to device {device.hostname}: {str(e)}")
                errors.append({"device": device.hostname, "message": str(e)})
                socketio.emit('overall_progress', {
                    'device': device.hostname,
                    'progress': 0,
                    'stage': 'Error',
                    'fail': str(e)
                })

            except Exception as e:
                # Handle any general errors
                logging.error(f"General error for device {device.hostname}: {str(e)}")
                errors.append({"device": device.hostname, "message": str(e)})
                socketio.emit('overall_progress', {
                    'device': device.hostname,
                    'progress': 0,
                    'stage': 'Error',
                    'error': str(e)
                })

        # After processing all devices, return success or error response
        if errors:
            logging.info(f"Errors occurred: {errors}")
            return jsonify({"success": False, "errors": errors}), 500
        else:
            return jsonify({"success": True, "message": "All configurations saved successfully"})

    @app.route('/restore_all_device_configs', methods=['POST'])
    @login_required
    def restore_all_device_configs():
        # Ensure the UPLOAD_FOLDER exists in the config
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash('Please login again', 'error')
            return jsonify({'success': False, 'error': 'Please login again'}), 401

        # Fetch all devices for the current user from the database
        devices = db.session.query(DeviceInfo).filter_by(user_id=current_user.id).all()

        if not devices:
            return jsonify({"success": False, "error": "No devices found for this user"}), 400

        errors = []
        user_folder = os.path.join(current_app.config['DEVICE_CONFIG_FOLDER'], str(current_user.username))

        # Check if user-specific folder exists where configurations are stored
        if not os.path.exists(user_folder):
            logging.info(f"Error: No configurations found to restore {user_folder}")
            return jsonify({"success": False, "error": "No configurations found to restore"}), 400

        total_devices = len(devices)
        completed_devices = 0

        # Loop through each device and attempt to restore the configuration
        for index, device in enumerate(devices):
            config_filename = f"{device.hostname}_config.txt"
            config_filepath = os.path.join(user_folder, config_filename)

            # Check if the config file exists for the device
            if not os.path.exists(config_filepath):
                errors.append({"device": device.hostname, "message": "Configuration file not found"})
                socketio.emit('overall_progress', {
                    'device': device.hostname,
                    'progress': 0,
                    'stage': 'Error',
                    'error': 'Configuration file not found'
                })
                continue

            try:
                # Open and clean the configuration file (ignoring lines starting with "##")
                with open(config_filepath, 'r') as config_file:
                    config_lines = config_file.readlines()
                    clean_config_lines = [line for line in config_lines if not line.startswith("##")]
                    config_format = 'set' if any(line.startswith('set ') for line in clean_config_lines) else 'text'

                    # Transfer the configuration to the router (you may need to implement transfer_file_to_router)
                    transfer_status = transfer_file_to_router(
                        clean_config_lines, device.ip, device.username,
                        device.password, device.hostname, config_format
                    )

                    # Handle failure during the config transfer
                    if "successfully" not in transfer_status:
                        logging.error(f"General error for device {device.hostname}: {transfer_status}")
                        errors.append({"device": device.hostname, "message": transfer_status})
                        socketio.emit('overall_progress', {
                            'device': device.hostname,
                            'progress': 0,
                            'stage': 'Error',
                            'error': transfer_status
                        })
                    else:
                        # If the config was transferred successfully
                        completed_devices += 1
                        progress = int((completed_devices / total_devices) * 100)

                        socketio.emit('overall_progress', {
                            'device': device.hostname,
                            'progress': progress,
                            'stage': 'Completed'
                        })

            except Exception as e:
                # Catch any other errors and log them
                logging.error(f"General error for device {device.hostname}: {str(e)}")
                errors.append({"device": device.hostname, "message": str(e)})
                socketio.emit('overall_progress', {
                    'device': device.hostname,
                    'progress': 0,
                    'stage': 'Error',
                    'error': str(e)
                })

        # Return success or errors after processing all devices
        if errors:
            logging.info(f"Errors occurred: {errors}")
            return jsonify({"success": False, "errors": errors}), 500
        else:
            return jsonify({"success": True, "message": "All configurations restored successfully"})

    @app.route('/api/devices', methods=['GET'])
    @login_required
    def get_devices():
        devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
        devices_data = [{'id': device.id, 'hostname': device.hostname, 'ip': device.ip, 'username': device.username,
                         'password': device.password} for device in devices]
        return jsonify(devices_data)

    ## Trigger Event ##

    @app.route('/trigger_events', methods=['GET', 'POST'])
    @login_required
    def trigger_events():
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash('Please login again', 'error')
            return redirect(url_for('index'))

        if request.method == 'POST':
            if request.is_json:
                data = request.get_json()
                description = data.get('description')
                iteration = data.get('iteration')
                device_name = data.get('device_name')
                command = data.get('command')
                new_event = TriggerEvent(
                    description=description,
                    iteration=iteration,
                    device_name=device_name,
                    user_id=current_user.id,
                    command=command
                )
                db.session.add(new_event)
                db.session.commit()

                return jsonify({"success": True, "id": new_event.id, "message": "Event saved successfully"})
            else:
                return jsonify({"success": False, "message": "Invalid request"}), 400

        # For GET requests, return the list of devices
        devices = get_router_details_from_db()
        return jsonify({"devices": devices})

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

    @app.route('/delete_event/<int:event_id>', methods=['POST'])
    @login_required
    def delete_event(event_id):
        event = TriggerEvent.query.get(event_id)
        if event:
            db.session.delete(event)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Event deleted successfully'})
        return jsonify({'success': False, 'message': 'Event not found'}), 404


    @app.route('/view_events', methods=['GET'])
    @login_required
    def view_events():
        events = TriggerEvent.query.filter_by(user_id=current_user.id).all()
        return render_template('view_events.html', events=events)


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


    ## generate underlay configuration for Discover topology useing lldp and  Configure network ##

    '''@app.route('/show_underlay_lldp_config', methods=['POST'])
    @login_required
    def show_underlay_lldp_config():
        if not current_user.is_authenticated:
            flash('Please login again', 'error')
            return jsonify({'success': False, 'error': 'Please login again'}), 401
        config_method = request.form.get('config_method')
        delete_underlay_group = request.form.get('delete_group') == "on"
        use_ipv4 = request.form.get('ipv4_underlay') == "on"
        use_ipv6 = request.form.get('ipv6_underlay') == "on"
        commands = defaultdict(list)
        local_as_mapping = {}
        ip_assignments = {}
        neighbors_dict = defaultdict(list)
        as_counter = 65000
        success_hosts = []
        device_list=[]
        failed_hosts = set()
        logging.info(f"Configuration method selected: {config_method}")
        logging.info(f"Current user ID: {current_user.id}")
        devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
        if not devices:
            logging.info(f"No devices found for user {current_user.id}")
            flash('No devices found for the current user.', 'error')
            return redirect(url_for('index'))

        # Prepare the local AS mapping
        for device in devices:
            device_list.append(device.hostname)
            if device.hostname not in local_as_mapping:
                local_as_mapping[device.hostname] = as_counter
                as_counter += 1
        logging.info(f"**fetching lldp connections for {device_list}")
        # Fetch LLDP neighbors for each device with exception handling

        for device in devices:
            try:
                dev_connector = DeviceConnectorClass(device.hostname, device.ip, device.username,device.password)
                dev = dev_connector.connect_to_device()
                lldp_builder = BuildLLDPConnectionClass(device.hostname,device_list)
                neighbors = lldp_builder.get_lldp_neighbors(dev)
                logging.info(f"**lldp neighbors: {neighbors}")
                # Combine neighbors into the global dictionary
                for host, data in neighbors.items():
                    neighbors_dict[host].extend(data)
                success_hosts.append(device.hostname)
                # Simplify neighbors dict (remove domain from hostnames)
                simplified_neighbors = lldp_builder.simplify_neighbors_dict(neighbors_dict)
                logging.info(f"simplified_neighbors: {simplified_neighbors}")
                # Build connections from the neighbor data
                connections = lldp_builder.build_connections(simplified_neighbors)
                logging.info(f"**lldp connections: {connections}")
                # Generate the configuration
                generate_config(commands, connections, local_as_mapping, delete_underlay_group, use_ipv4, use_ipv6,ip_assignments)
            except ConnectAuthError as e:
                logging.error(f"Connection authentication error for device {device.hostname}: {str(e)}")
                failed_hosts.add((device.hostname, f"Connection authentication error: {str(e)}"))
            except ConnectError as e:
                logging.error(f"Connection error for device {device.hostname}: {str(e)}")
                failed_hosts.add((device.hostname, f"Connection error: {str(e)}"))
            except Exception as e:
                logging.error(f"Error fetching LLDP neighbors for device {device.hostname}: {str(e)}")
                failed_hosts.add((device.hostname, f"Error: {str(e)}"))
        # Save each device's configuration to a file
        #user_folder = os.path.join(current_app.config['UPLOAD_FOLDER'])
        user_folder = os.path.join(current_app.config['DEVICE_CONFIG_FOLDER'], str(current_user.username))
        os.makedirs(user_folder, exist_ok=True)
        for hostname, cmds in commands.items():
            config_filename = f"{hostname}_config.txt"
            config_filepath = os.path.join(user_folder, config_filename)
            with open(config_filepath, 'w') as config_file:
                config_file.write("\n".join(cmds))
        session['generated_config'] = commands
        devices = get_router_details_from_db()
        return render_template('underlay_config_result.html', success_hosts=success_hosts,failed_hosts=list(failed_hosts), commands=commands, devices=devices)'''

    '''@app.route('/show_underlay_lldp_config', methods=['POST'])
    @login_required
    def show_underlay_lldp_config():
        if not current_user.is_authenticated:
            flash('Please login again', 'error')
            return jsonify({'success': False, 'error': 'Please login again'}), 401

        config_method = request.form.get('config_method')
        delete_underlay_group = request.form.get('delete_group') == "on"
        use_ipv4 = request.form.get('ipv4_underlay') == "on"
        use_ipv6 = request.form.get('ipv6_underlay') == "on"
        commands = defaultdict(list)
        local_as_mapping = {}
        ip_assignments = {}
        neighbors_dict = defaultdict(list)
        as_counter = 65000
        success_hosts = []
        failed_hosts = set()
        device_list = []

        devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
        if not devices:
            flash('No devices found for the current user.', 'error')
            return redirect(url_for('index'))

        total_devices = len(devices)
        progress_increment = 100 // total_devices
        current_progress = 0
        # Prepare the local AS mapping and ensure device has a valid hostname
        for device in devices:
            if device and device.hostname:  # Ensure device and hostname are valid
                device_name = device.hostname.strip()
                if device_name:
                    device_list.append(device_name)
                    if device_name not in local_as_mapping:
                        local_as_mapping[device_name] = as_counter
                        as_counter += 1
                else:
                    logging.error(f"Skipping device with empty hostname: {device.ip}")
                    continue
            else:
                logging.error(f"Skipping device due to missing hostname or invalid device object: {device}")
                continue
        for index, device in enumerate(devices):
            device_name = device.hostname.strip() if device and device.hostname else None  # Ensure device name is defined
            if not device_name:
                logging.error(f"Skipping device with undefined hostname at index {index}")
                continue  # Skip further processing for undefined devices
            try:
                dev_connector = DeviceConnectorClass(device.hostname, device.ip, device.username, device.password)
                dev = dev_connector.connect_to_device()
                lldp_builder = BuildLLDPConnectionClass(device.hostname, device_list)

                # Emit progress for simplified_neighbors
                neighbors = lldp_builder.get_lldp_neighbors(dev)
                current_progress += progress_increment // 3  # Increment by one-third for each step
                socketio.emit('overall_progress', {
                    'device': device.hostname,
                    'progress': current_progress,
                    'stage': 'simplified_neighbors'
                })

                # Combine neighbors into the global dictionary
                for host, data in neighbors.items():
                    neighbors_dict[host].extend(data)
                success_hosts.append(device.hostname)

                # Simplify neighbors dict (remove domain from hostnames)
                simplified_neighbors = lldp_builder.simplify_neighbors_dict(neighbors_dict)

                # Emit progress for lldp_builder
                current_progress += progress_increment // 3  # Another third for this stage
                socketio.emit('overall_progress', {
                    'device': device.hostname,
                    'progress': current_progress,
                    'stage': 'lldp_builder'
                })

                # Build connections from the neighbor data
                connections = lldp_builder.build_connections(simplified_neighbors)

                # Generate the configuration
                generate_config(commands, connections, local_as_mapping, delete_underlay_group, use_ipv4, use_ipv6,
                                ip_assignments)

                # Emit progress for generate_config
                current_progress += progress_increment // 3  # Final third for generating config
                socketio.emit('overall_progress', {
                    'device': device.hostname,
                    'progress': current_progress,
                    'stage': 'generate_config'
                })

            except (ConnectAuthError,ConnectUnknownHostError, SSHError, paramiko.SSHException, socket.error,ConnectError,ConnectionResetError) as e:
                # Handle connection errors and notify the progress bar
                error_message = f"Connection failed: {str(e)}"
                failed_hosts.add((device_name, error_message))

                socketio.emit('overall_progress', {
                    'device': device_name,
                    'progress': current_progress,
                    'stage': 'Error',
                    'fail': error_message
                })
                logging.error(f"Connection error for device {device_name}: {str(e)}")
                continue  # Skip further processing for this device

            except Exception as e:
                # Handle any other exceptions and notify the progress bar
                error_message = f"Unexpected error: {str(e)}"
                failed_hosts.add((device_name, error_message))
                socketio.emit('overall_progress', {
                    'device': device_name,
                    'progress': current_progress,
                    'stage': 'Error',
                    'fail': error_message
                })
                logging.error(f"Unexpected error during LLDP configuration for device {device_name}: {str(e)}")
                continue  # Skip further processing for this device


        # Save each device's configuration to a file
        user_folder = os.path.join(current_app.config['DEVICE_CONFIG_FOLDER'], str(current_user.username))
        os.makedirs(user_folder, exist_ok=True)
        for hostname, cmds in commands.items():
            config_filename = f"{hostname}_config.txt"
            config_filepath = os.path.join(user_folder, config_filename)
            with open(config_filepath, 'w') as config_file:
                config_file.write("\n".join(cmds))

        # Emit final progress update for get_router_details_from_db
        devices = get_router_details_from_db()
        socketio.emit('overall_progress', {
            'progress': 100,
            'stage': 'Completed'
        })
        time.sleep(5)

        return render_template('underlay_config_result.html', success_hosts=success_hosts,
                               failed_hosts=list(failed_hosts), commands=commands, devices=devices)'''



    @app.route('/show_configs_underlay_lldp')
    @login_required
    def show_configs_underlay_lldp():
        # Retrieve the commands from the session
        commands = session.get('commands', {})

        if not commands:
            flash('No configuration data available. Please try again.', 'error')
            return redirect(url_for('show_underlay_lldp_config'))

        # Retrieve devices for the user
        devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()

        # Pass the commands to the template instead of config_data
        return render_template('underlay_config_result.html', commands=commands, devices=devices)

    @app.route('/show_underlay_lldp_config', methods=['POST'])
    @login_required
    def show_underlay_lldp_config():
        try:
            if not current_user.is_authenticated:
                flash('Please login again', 'error')
                return jsonify({'success': False, 'error': 'Please login again'}), 401

            config_method = request.form.get('config_method')
            delete_underlay_group = request.form.get('delete_group') == "on"
            use_ipv4 = request.form.get('ipv4_underlay') == "on"
            use_ipv6 = request.form.get('ipv6_underlay') == "on"
            commands = defaultdict(list)
            local_as_mapping = {}
            ip_assignments = {}
            neighbors_dict = defaultdict(list)
            as_counter = 65000
            success_hosts = []
            failed_hosts = set()
            device_list = []

            devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
            if not devices:
                flash('No devices found for the current user.', 'error')
                return redirect(url_for('index'))

            total_devices = len(devices)
            progress_increment = 100 // total_devices if total_devices > 0 else 0
            current_progress = 0

            # Prepare the local AS mapping and ensure device has a valid hostname
            for device in devices:
                if device and device.hostname:  # Ensure device and hostname are valid
                    device_name = device.hostname.strip()
                    if device_name:
                        device_list.append(device_name)
                        if device_name not in local_as_mapping:
                            local_as_mapping[device_name] = as_counter
                            as_counter += 1
                    else:
                        logging.error(f"Skipping device with empty hostname: {device.ip}")
                        continue
                else:
                    logging.error(f"Skipping device due to missing hostname or invalid device object: {device}")
                    continue

            for index, device in enumerate(devices):
                device_name = device.hostname.strip() if device and device.hostname else None  # Ensure device name is defined
                if not device_name:
                    logging.error(f"Skipping device with undefined hostname at index {index}")
                    continue  # Skip further processing for undefined devices

                try:
                    # Attempt to connect to the device
                    dev_connector = DeviceConnectorClass(device_name, device.ip, device.username, device.password)
                    dev = dev_connector.connect_to_device()
                    logging.info(f"Connected to {device_name}")

                    # Fetch LLDP neighbors
                    lldp_builder = BuildLLDPConnectionClass(device_name, device_list)
                    neighbors = lldp_builder.get_lldp_neighbors(dev)

                    # Emit progress after getting neighbors
                    current_progress += progress_increment // 3
                    socketio.emit('overall_progress', {
                        'device': device_name,
                        'progress': current_progress,
                        'stage': 'simplified_neighbors'
                    })

                    # Combine neighbors into the global dictionary
                    for host, data in neighbors.items():
                        neighbors_dict[host].extend(data)
                    success_hosts.append(device_name)

                    # Simplify neighbors dictionary
                    simplified_neighbors = lldp_builder.simplify_neighbors_dict(neighbors_dict)

                    # Emit progress after simplifying neighbors
                    current_progress += progress_increment // 3
                    socketio.emit('overall_progress', {
                        'device': device_name,
                        'progress': current_progress,
                        'stage': 'lldp_builder'
                    })

                    # Build connections from neighbors and generate configuration
                    connections = lldp_builder.build_connections(simplified_neighbors)
                    generate_config(commands, connections, local_as_mapping, delete_underlay_group, use_ipv4, use_ipv6,
                                    ip_assignments)

                    # Emit progress after generating configuration
                    current_progress += progress_increment // 3
                    socketio.emit('overall_progress', {
                        'device': device_name,
                        'progress': current_progress,
                        'stage': 'generate_config'
                    })


                except (ConnectAuthError, ConnectUnknownHostError, SSHError, paramiko.SSHException, socket.error,
                        ConnectionResetError) as e:
                    # Handle connection errors and notify the progress bar
                    error_message = f"Connection failed: {str(e)}"
                    failed_hosts.add((device_name, error_message))

                    socketio.emit('overall_progress', {
                        'device': device_name,
                        'progress': current_progress,
                        'stage': 'Error',
                        'fail': error_message
                    })
                    logging.error(f"Connection error for device {device_name}: {str(e)}")
                    continue  # Skip further processing for this device

                except Exception as e:
                    # Handle any other exceptions and notify the progress bar
                    error_message = f"Unexpected error: {str(e)}"
                    failed_hosts.add((device_name, error_message))
                    socketio.emit('overall_progress', {
                        'device': device_name,
                        'progress': current_progress,
                        'stage': 'Error',
                        'fail': error_message
                    })
                    logging.error(f"Unexpected error during LLDP configuration for device {device_name}: {str(e)}")
                    continue  # Skip further processing for this device

            session['commands'] = commands
            # Emit final progress update to report status
            final_message = "Configuration complete with some errors" if failed_hosts else "Configuration completed successfully"
            #print(f"commands: {commands}")
            socketio.emit('overall_progress', {
                'progress': 100,
                'stage': 'Completed',
                'message': final_message,
                'failed_hosts': list(failed_hosts),
                'success_hosts': success_hosts
            })


            return '', 200  # Return an empty response so that AJAX call does not expect any redirect

        except Exception as main_error:
            error_traceback = traceback.format_exc()
            logging.error(f"Unexpected error during LLDP configuration: {error_traceback}")

            # Emit detailed error message via socket
            socketio.emit('overall_progress', {
                'progress': 0,
                'stage': 'Error',
                'fail': f"Unexpected error: {error_traceback}"
            })

            return '', 500

    @app.route('/show_underlay_csv_config', methods=['POST'])
    @login_required
    def show_underlay_csv_config():
        csv_file = request.files.get('csv_file')  # Changed to .get to handle missing file
        delete_underlay_group = request.form.get('delete_group') == "on"
        use_ipv4 = request.form.get('ipv4_underlay') == "on"
        use_ipv6 = request.form.get('ipv6_underlay') == "on"
        as_counter = 65000
        # Check if file is uploaded
        if not csv_file or csv_file.filename == '':
            flash('No selected file', 'error')
            return redirect(url_for('index'))

        # Check file type
        if csv_file and csv_file.filename.endswith('.csv'):
            filename = secure_filename(csv_file.filename)
            filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            csv_file.save(filepath)

            # Process CSV file
            with open(filepath, mode='r') as file:
                csv_reader = csv.DictReader(file)
                connections = []
                local_as_mapping = {}
                remote_as_mapping = {}
                ip_assignments = {}
                seen = set()
                duplicates = []
                duplicate_device_interfaces = []
                for row in csv_reader:
                    # Create a tuple to represent the device-interface pairs for both sides of the connection
                    connection_tuple_1 = (row['device1'], row['interface1'])
                    connection_tuple_2 = (row['device2'], row['interface2'])
                    # Check for duplicates based on either side of the connection
                    if connection_tuple_1 in seen or connection_tuple_2 in seen:
                        duplicates.append({row['device1']: row['interface1'], row['device2']: row['interface2']})
                        if connection_tuple_1 in seen:
                            duplicate_device_interfaces.append(
                                f"Duplicate device/interface found: {row['device1']} using {row['interface1']}")
                        if connection_tuple_2 in seen:
                            duplicate_device_interfaces.append(
                                f"Duplicate device/interface found: {row['device2']} using {row['interface2']}")
                    else:
                        # Add both sides of the connection to the seen set
                        seen.add(connection_tuple_1)
                        seen.add(connection_tuple_2)
                        # Add the unique connection
                        connections.append({row['device1']: row['interface1'], row['device2']: row['interface2']})

                if duplicates:
                    logging.warning("Duplicate data found")
                    return render_template('underlay_config_result.html',
                                           duplicate_error={
                                               'message': 'Duplicate data found: same device/interface used multiple times.',
                                               'details': duplicate_device_interfaces},
                                           success_hosts=[], failed_hosts=[], commands={}), 400

                devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
                #logging.info(f"Devices found: {devices}")
                if not devices:
                    logging.info(f"No devices found for user {current_user.id}")
                    flash('No devices found for the current user.', 'error')
                    return redirect(url_for('index'))
                for device in devices:
                    logging.info(f"Devices found: {devices}")
                    if device.hostname not in local_as_mapping:
                        local_as_mapping[device.hostname] = as_counter
                        as_counter += 1
                # Log connections and AS mappings for debugging
                logging.info(f"Connections: {connections}")
                logging.info(f"Local AS Mapping: {local_as_mapping}")
                logging.info(f"Remote AS Mapping: {remote_as_mapping}")
                logging.info(f"IP Assignments: {ip_assignments}")

                # Generate configuration based on the CSV data
                commands = defaultdict(list)
                generate_config(commands, connections, local_as_mapping, delete_underlay_group,use_ipv4, use_ipv6, ip_assignments)
                # generate_config(commands, connections, local_as_mapping, remote_as_mapping, delete_underlay_group,use_ipv4, use_ipv6, ip_assignments)
                # Save each device's configuration to a file
                user_folder = os.path.join(current_app.config['UPLOAD_FOLDER'])
                os.makedirs(user_folder, exist_ok=True)

                for hostname, cmds in commands.items():
                    config_filename = f"{hostname}_config.txt"
                    config_filepath = os.path.join(user_folder, config_filename)
                    with open(config_filepath, 'w') as config_file:
                        config_file.write("\n".join(cmds))

                # Log generated commands for debugging
                logging.info(f"Generated Commands: {commands}")
                # Flash success message and return
                flash('Configuration generated from CSV.', 'success')
                devices = get_router_details_from_db()
                return render_template('underlay_config_result.html', connections=connections, commands=commands, devices=devices)
        flash('Invalid file format. Please upload a CSV file.', 'error')
        return redirect(url_for('index'))

    '''@app.route('/save_underlay_topology_lldp', methods=['POST'])
    def save_underlay_topology_lldp():
        if not current_user.is_authenticated:
            flash('Please login again', 'error')
            return jsonify({'success': False, 'error': 'Please login again'}), 401
        local_as_mapping = {}
        neighbors_dict = defaultdict(list)
        as_counter = 65000
        success_hosts = []
        device_list = []
        devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
        unique_connections=[]
        if not devices:
            flash('No devices found for the current user.', 'error')
            return redirect(url_for('index'))

        total_devices = len(devices)
        progress_increment = 100 // total_devices
        current_progress = 0
        seen = set()
        # Prepare the local AS mapping
        for device in devices:
            device_list.append(device.hostname)
            if device.hostname not in local_as_mapping:
                local_as_mapping[device.hostname] = as_counter
                as_counter += 1

        for index, device in enumerate(devices):
            try:
                dev_connector = DeviceConnectorClass(device.hostname, device.ip, device.username, device.password)
                dev = dev_connector.connect_to_device()
                lldp_builder = BuildLLDPConnectionClass(device.hostname, device_list)
                # Emit progress for simplified_neighbors
                neighbors = lldp_builder.get_lldp_neighbors(dev)
                # Combine neighbors into the global dictionary
                for host, data in neighbors.items():
                    neighbors_dict[host].extend(data)
                success_hosts.append(device.hostname)
                # Simplify neighbors dict (remove domain from hostnames)
                simplified_neighbors = lldp_builder.simplify_neighbors_dict(neighbors_dict)
                # Build connections from the neighbor data
                connections = lldp_builder.build_connections(simplified_neighbors)
                for connection in connections:
                    # Convert each connection to a tuple of sorted items to handle bidirectional connections
                    sorted_connection = tuple(sorted(connection.items()))
                    if sorted_connection not in seen:
                        seen.add(sorted_connection)
                        unique_connections.append(connection)
            except Exception as e:
                print(f"Error: {str(e)}")
        print(f"unique_connections: {unique_connections}")
        csv_content = "device1,interface1,device2,interface2\n"
        skip_interfaces = {'re0:mgmt-0', 'em0', 'fxp0'}
        skip_device_patterns = ['mgmt', 'management', 'hypercloud']
        interface_pattern = r"^(et|ge|xe|em|re|fxp)\-[0-9]+\/[0-9]+\/[0-9]+(:[0-9]+)?$"
        for connection in unique_connections:
            # Get the device and interface keys dynamically
            keys = list(connection.keys())
            # Ensure the connection has at least two devices
            if len(keys) < 2:
                print(f"Skipping connection with only one device: {connection}")
                continue
            device1 = keys[0]
            device2 = keys[1]
            interface1 = connection[device1]
            interface2 = connection[device2]
            # Skip connections with interfaces in skip_interfaces
            if interface1 in skip_interfaces or interface2 in skip_interfaces:
                print(
                    f"Skipping connection with ignored interfaces: {device1} ({interface1}), {device2} ({interface2})")
                continue
            # Skip connections if devices match skip_device_patterns
            if any(pattern in device1.lower() for pattern in skip_device_patterns) or \
                    any(pattern in device2.lower() for pattern in skip_device_patterns):
                print(f"Skipping connection with ignored device patterns: {device1}, {device2}")
                continue
            # Validate interfaces using the regex pattern
            if not re.match(interface_pattern, interface1) or not re.match(interface_pattern, interface2):
                print(
                    f"Skipping connection due to invalid interface format: {device1} ({interface1}), {device2} ({interface2})")
                continue
            csv_content += f"{device1},{interface1},{device2},{interface2}\n"
        logging.info(f"Saviing LLDP neighbors to user database: {csv_content}")
        topology = Topology(user_id=current_user.id, csv_data=str(csv_content))
        db.session.add(topology)
        db.session.commit()
        logging.info('Saved topology to database for user: %s', current_user.username)
        return jsonify({'success': True, 'connections': unique_connections})'''

    @app.route('/save_underlay_topology_lldp', methods=['POST'])
    def save_underlay_topology_lldp():
        if not current_user.is_authenticated:
            flash('Please login again', 'error')
            return jsonify({'success': False, 'error': 'Please login again'}), 401

        local_as_mapping = {}
        neighbors_dict = defaultdict(list)
        as_counter = 65000
        success_hosts = []
        device_list = []
        devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
        unique_connections = []

        if not devices:
            flash('No devices found for the current user.', 'error')
            return redirect(url_for('index'))

        total_devices = len(devices)
        progress_increment = 100 // total_devices
        current_progress = 0
        seen = set()

        # Prepare the local AS mapping
        for device in devices:
            device_list.append(device.hostname)
            if device.hostname not in local_as_mapping:
                local_as_mapping[device.hostname] = as_counter
                as_counter += 1

        for index, device in enumerate(devices):
            try:
                dev_connector = DeviceConnectorClass(device.hostname, device.ip, device.username, device.password)
                dev = dev_connector.connect_to_device()

                lldp_builder = BuildLLDPConnectionClass(device.hostname, device_list)
                neighbors = lldp_builder.get_lldp_neighbors(dev)

                # Combine neighbors into the global dictionary
                for host, data in neighbors.items():
                    neighbors_dict[host].extend(data)
                success_hosts.append(device.hostname)

                # Simplify neighbors dict (remove domain from hostnames)
                simplified_neighbors = lldp_builder.simplify_neighbors_dict(neighbors_dict)
                connections = lldp_builder.build_connections(simplified_neighbors)

                for connection in connections:
                    sorted_connection = tuple(sorted(connection.items()))
                    if sorted_connection not in seen:
                        seen.add(sorted_connection)
                        unique_connections.append(connection)

                # Emit progress increment via SocketIO
                current_progress += progress_increment
                socketio.emit('overall_progress', {
                    'device': device.hostname,
                    'progress': current_progress,
                    'stage': 'In progress',
                    'fail': None,
                    'error': None
                })

            except Exception as e:
                logging.error(f"Error processing device {device.hostname}: {str(e)}")
                socketio.emit('overall_progress', {
                    'device': device.hostname,
                    'progress': current_progress,
                    'stage': 'Error',
                    'fail': str(e),
                    'error': str(e)
                })
                return jsonify({'success': False, 'error': f"Error processing device {device.hostname}: {str(e)}"}), 500

        logging.info(f"Unique connections: {unique_connections}")

        csv_content = "device1,interface1,device2,interface2\n"
        skip_interfaces = {'re0:mgmt-0', 'em0', 'fxp0'}
        skip_device_patterns = ['mgmt', 'management', 'hypercloud']
        interface_pattern = r"^(et|ge|xe|em|re|fxp)\-[0-9]+\/[0-9]+\/[0-9]+(:[0-9]+)?$"

        for connection in unique_connections:
            keys = list(connection.keys())
            if len(keys) < 2:
                logging.warning(f"Skipping connection with only one device: {connection}")
                continue
            device1 = keys[0]
            device2 = keys[1]
            interface1 = connection[device1]
            interface2 = connection[device2]

            if interface1 in skip_interfaces or interface2 in skip_interfaces:
                logging.info(
                    f"Skipping connection with ignored interfaces: {device1} ({interface1}), {device2} ({interface2})")
                continue

            if any(pattern in device1.lower() for pattern in skip_device_patterns) or \
                    any(pattern in device2.lower() for pattern in skip_device_patterns):
                logging.info(f"Skipping connection with ignored device patterns: {device1}, {device2}")
                continue

            if not re.match(interface_pattern, interface1) or not re.match(interface_pattern, interface2):
                logging.warning(
                    f"Skipping connection due to invalid interface format: {device1} ({interface1}), {device2} ({interface2})")
                continue

            csv_content += f"{device1},{interface1},{device2},{interface2}\n"

        logging.info(f"Saving LLDP neighbors to user database: {csv_content}")
        try:
            topology = Topology(user_id=current_user.id, csv_data=str(csv_content))
            db.session.add(topology)
            db.session.commit()
            logging.info('Saved topology to database for user: %s', current_user.username)
        except Exception as e:
            logging.error(f"Failed to save topology to the database: {str(e)}")
            socketio.emit('overall_progress', {
                'device': 'Database',
                'progress': current_progress,
                'stage': 'Error',
                'fail': str(e),
                'error': str(e)
            })
            return jsonify({'success': False, 'error': f"Failed to save topology: {str(e)}"}), 500

        socketio.emit('overall_progress', {
            'device': 'All Devices',
            'progress': 100,
            'stage': 'Completed',
            'fail': None,
            'error': None
        })

        return jsonify({'success': True, 'connections': unique_connections, 'progress': 100})

    @app.route('/save_underlay_topology_csv', methods=['POST'])
    @login_required
    def save_underlay_topology_csv():
        csv_file = request.files.get('csv_file')

        # Check if a file was selected
        if not csv_file or csv_file.filename == '':
            logging.error('No selected file')
            return jsonify({'error': 'No selected file'}), 400

        # Ensure the file is a CSV
        if csv_file and csv_file.filename.endswith('.csv'):
            filename = secure_filename(csv_file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            try:
                # Save the file
                csv_file.save(filepath)
                logging.info('Saved file to %s', filepath)

                # Read the file content after saving
                csv_file.seek(0)  # Reset file pointer to the beginning
                file_content = io.StringIO(csv_file.read().decode('utf-8'), newline=None)
                csv_reader = csv.DictReader(file_content)

                # Prepare the CSV data for storage
                csv_data = 'device1,interface1,device2,interface2\n' + '\n'.join(
                    [','.join(row.values()) for row in csv_reader])
                logging.info('Parsed CSV data: %s', csv_data)

                # Save the parsed topology to the database
                topology = Topology(user_id=current_user.id, csv_data=csv_data)
                db.session.add(topology)
                db.session.commit()

                logging.info('Saved topology to database for user: %s', current_user.username)
                return jsonify({'success': True})

            except Exception as e:
                logging.error('Error processing the CSV file: %s', str(e))
                return jsonify({'error': 'Failed to process the CSV file'}), 500

        # If file is not a CSV
        logging.error('Invalid file format. Only CSV files are allowed.')
        return jsonify({'error': 'Invalid file format. Only CSV files are allowed.'}), 400






    @app.route('/upload_config', methods=['GET', 'POST'])
    @login_required
    def upload_config():
        if request.method == 'POST':
            config_file = request.files.get('file')
            config_text = request.form.get('config_textarea')
            router_ips = request.form['router_ips'].split(',')  # IPs still provided in form
            # Query device information from the database based on the logged-in user
            devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
            device_credentials = {device.ip: {'username': device.username, 'password': device.password} for device in
                                  devices}
            def emit_progress(router_ip, progress, error=None):
                socketio.emit('progress', {'ip': router_ip, 'progress': progress, 'error': error}, namespace='/')

            def handle_device(router_ip, config_to_load, config_format, results, max_retries=3, retry_delay=5):
                attempt = 1
                while attempt <= max_retries:
                    try:
                        emit_progress(router_ip, 0)

                        # Retrieve device credentials from the database
                        if router_ip not in device_credentials:
                            raise ValueError(f"Credentials not found for device {router_ip}")

                        router_user = device_credentials[router_ip]['username']
                        router_password = device_credentials[router_ip]['password']

                        dev = Device(host=router_ip, user=router_user, passwd=router_password, port=22)
                        dev.open()
                        emit_progress(router_ip, 25)
                        cu = Config(dev)

                        # Lock configuration
                        cu.lock()
                        emit_progress(router_ip, 50)

                        # Load configuration
                        cu.load(config_to_load, format=config_format, ignore_warning=True)
                        emit_progress(router_ip, 75)

                        # Commit configuration
                        cu.commit()

                        # Unlock configuration
                        cu.unlock()
                        dev.close()
                        emit_progress(router_ip, 100)
                        results[router_ip] = {'success': True, 'message': 'Configuration loaded successfully'}
                        break  # Success, exit loop

                    except LockError as e:
                        logging.warning(
                            f"LockError on {router_ip}. Retrying after rollback (Attempt {attempt}/{max_retries})")
                        emit_progress(router_ip, 0, error="Configuration database locked. Retrying after rollback...")

                        # Rollback and retry
                        try:
                            cu.rollback()  # Rollback to the previous state
                            cu.unlock()  # Unlock the configuration
                            logging.info(f"Rollback successful on {router_ip}")
                        except UnlockError:
                            logging.warning(f"UnlockError on {router_ip}. Could not unlock after rollback.")
                        except Exception as rollback_error:
                            logging.error(f"Error during rollback on {router_ip}: {str(rollback_error)}")

                        # Wait before retrying
                        if attempt < max_retries:
                            time.sleep(retry_delay)
                        else:
                            results[router_ip] = {'success': False,
                                                  'message': f"LockError on {router_ip}. Max retries reached."}
                            emit_progress(router_ip, 0,
                                          error=f"Max retries reached on {router_ip}. Could not lock config.")
                        attempt += 1

                    except (ConnectAuthError, ConnectError, ConfigLoadError, CommitError) as e:
                        logging.error(f"Error loading configuration on {router_ip}: {str(e)}")
                        emit_progress(router_ip, 0, error=str(e))
                        results[router_ip] = {'success': False, 'message': str(e)}
                        break

                    except Exception as e:
                        logging.error(f"Unexpected error on {router_ip}: {str(e)}")
                        emit_progress(router_ip, 0, error=str(e))
                        results[router_ip] = {'success': False, 'message': str(e)}
                        break

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
            clean_config_lines = [line for line in config_lines if line.strip() and not line.startswith("#")]
            config_to_load = "\n".join(clean_config_lines)
            #logging.info(f"Configuration to load: {config_to_load}")

            results = {}
            threads = []

            for router_ip in router_ips:
                thread = threading.Thread(target=handle_device, args=(
                    router_ip.strip(), config_to_load, config_format, results))
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
                return render_template('index.html')
            if 'LOG_FOLDER' not in current_app.config:
                flash('Pls login again', 'error')
                return render_template('index.html')
        if request.method == 'POST':
            def parse_ip_parts(ip_parts_str, last_octet):
                parts = ip_parts_str.split('/')
                ip_v4 = {}
                ip_v6 = {}
                for part in parts:
                    try:
                        if ':' in part:
                            full_ip = f"{part}{last_octet}"
                            v6 = ipaddress.IPv6Address(full_ip)
                            ip_v6['ipv6'] = part
                        elif '.' in part:
                            full_ip = f"{part}.{last_octet}"
                            v4 = ipaddress.IPv4Address(full_ip)
                            ip_v4['ipv4'] = part
                    except ipaddress.AddressValueError:
                        logging.info(f"IP AddressValueError: {e}")
                        continue
                return {**ip_v4, **ip_v6}

            base_ip_parts_str = request.form['base_ip_parts']
            last_octet = int(request.form['last_octet'])
            base_ip_parts = parse_ip_parts(base_ip_parts_str, last_octet)

            # base_ip_parts = list(map(int, request.form['base_ip_parts'].split('.')))
            ip_versions = request.form.getlist('ip_version')
            if not isinstance(ip_versions, list):
                ip_versions = [ip_versions]

            interface_prefixes = request.form['interface_prefixes'].split()
            base_vlan_id = int(request.form['base_vlan_id'])
            filename = request.form.get('filename', 'config.txt')
            access = 'access' in request.form
            if access:
                num_vlans_per_interface = 1
            else:
                num_vlans_per_interface = int(request.form.get('num_vlans_per_interface'))
            trunk = 'trunk' in request.form
            # ip_versions = [ip_version for ip_version in request.form.getlist('ip_version')]
            native_vlanid = 'native_vlanid' in request.form
            native_vlanid_value = request.form.get('native_vlanid_value', '')

            all_config_lines = []
            current_vlan_id = base_vlan_id
            vlan_ids = [current_vlan_id + i for i in range(num_vlans_per_interface)]
            current_vlan_id += num_vlans_per_interface
            config_lines = generate_vlan_config(interface_prefixes, vlan_ids, base_ip_parts, access, trunk,
                                                native_vlanid, native_vlanid_value, ip_versions, last_octet)

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
            # devices = get_router_details_from_csv(os.path.join(current_app.config['UPLOAD_FOLDER'], 'device.csv'))
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
            # devices = get_router_details_from_csv(os.path.join(current_app.config['UPLOAD_FOLDER'], 'device.csv'))
            devices = get_router_details_from_db()
            return render_template('result_generate_vxlan_config.html', spine_configs=spine_configs,
                                   leaf_configs=leaf_configs, download_link=download_link,
                                   vxlan_filename=vxlan_filename, enumerate=enumerate, devices=devices)
        return render_template('index.html')

    @app.route('/bgp', methods=['POST'])
    @login_required
    def bgp():
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash('Pls login again', 'error')
            return redirect(url_for('index'))

        def parse_bgp_nei_ip_parts(ip_parts_str):
            parts = ip_parts_str.split('/')
            ip_v4 = {}
            ip_v6 = {}
            for part in parts:
                try:
                    if ':' in part:
                        full_ip = f"{part}"
                        v6 = ipaddress.IPv6Address(full_ip)
                        ip_v6['ipv6'] = part
                    elif '.' in part:
                        full_ip = f"{part}"
                        v4 = ipaddress.IPv4Address(full_ip)
                        ip_v4['ipv4'] = part
                except ipaddress.AddressValueError as e:
                    logging.info(f"BGP IP AddressValueError: {e}")
                    continue
            return {**ip_v4, **ip_v6}

        print(request.form)
        bgp_base_neighbor = request.form['bgp_base_neighbor']
        bgp_neighbor_ip_parts = parse_bgp_nei_ip_parts(bgp_base_neighbor)
        bgp_versions = request.form.getlist('bgp_version')
        initial_local_as = int(request.form['bgp_local_as'])
        initial_peer_as = int(request.form['bgp_as_number'])
        initial_peer_as = int(request.form['bgp_as_number'])
        bgp_type = request.form['bgp_type']
        bgp_interface_name_input = request.form['bgp_interface_name_input']
        neighbor_count = int(request.form['neighbor_count'])
        as_type = request.form['as_type']
        bgp_filename = request.form['bgp_filename']
        # config_lines = generate_bgp_scale_config(initial_local_as, initial_peer_as, bgp_base_neighbor, bgp_network,neighbor_count, as_type)
        config_lines = generate_bgp_scale_config(initial_local_as, initial_peer_as, neighbor_count, as_type,
                                                 bgp_neighbor_ip_parts, bgp_versions, bgp_type,
                                                 bgp_interface_name_input)
        config_text = "\n".join(config_lines)
        config_file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], bgp_filename)
        with open(config_file_path, "w") as config_file:
            config_file.write(config_text)

        # devices = get_router_details_from_csv(os.path.join(current_app.config['UPLOAD_FOLDER'], 'device.csv'))
        devices = get_router_details_from_db()
        download_link = True
        return render_template('result_generate_bgp_config.html', config_lines=config_lines, download_link=download_link,
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
        print(filename)
        print(router_ip)
        # router_user = request.form['router_user']
        # router_password = request.form['router_password']
        device_name = None

        devices = get_router_details_from_db()
        logging.info(devices)
        for device in devices:
            if device['ip'] == router_ip:
                router_user = device['username']
                router_password = device['password']
                device_name = device['hostname']
                break

        #config_file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        config_file_path = os.path.join(current_app.config['DEVICE_CONFIG_FOLDER'], str(current_user.username),filename)
        print(config_file_path)
        logging.info(f"Transfer file to device: {router_ip} - {config_file_path}")
        try:
            with open(config_file_path, 'r') as config_file:
                config_lines = config_file.readlines()
            config_format = "set"
            transfer_status = transfer_file_to_router(config_lines, router_ip, router_user, router_password,
                                                      device_name,
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


    @app.route('/vxlan', methods=['POST'])
    @login_required
    def vxlan():
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash('Please login again', 'error')
            return redirect(url_for('index'))

        # Retrieve the status of the checked radio button
        GenerateOverlayBtn_State = request.form.get('GenerateOverlayBtn', None)
        #print(f"GenerateOverlayBtn_State: {GenerateOverlayBtn_State}")

        # Retrieve the form data
        num_spines = int(request.form['num_spines'])
        num_leafs = int(request.form['num_leafs'])

        # For spine IPs
        spine_ips = [request.form.get(f'spine_ip_{i + 1}', None) for i in range(num_spines)]
        # For leaf IPs
        leaf_ips = [request.form.get(f'leaf_ip_{i + 1}', None) for i in range(num_leafs)]

        # Retrieve Service Intf Leaf values
        service_int_leaves = [request.form.get(f'service_int_{i}', None) for i in range(num_leafs)]

        # Retrieve Leaf Service Table values
        esi_lag_services = []
        for i in range(num_leafs):
            service_int = request.form.get(f'service_int_{i}', None)
            esi_lag_enabled = request.form.get(f'enable_esi_lag_{i}') == 'true'
            esi_id = request.form.get(f'esi_id_{i}', None)
            lacp_mode = request.form.get(f'lacp_mode_{i}', 'active')
            lag_intfs = request.form.get(f'lag_intfs_{i}', None)
            esi_lag_services.append({
                'service_int': service_int,
                'esi_lag_enabled': esi_lag_enabled,
                'esi_id': esi_id,
                'lacp_mode': lacp_mode,
                'lag_intfs': lag_intfs
            })

        # Retrieve and split the combined base IP input into IPv4 and IPv6 components
        base_ip_input = request.form['base_ip_parts']
        # Split the base IP input string (assumed to be 'IPv4/IPv6')
        base_ipv4_address, base_ipv6_address = base_ip_input.split('/')

        # Parse IPv4
        base_ip_parts = list(map(int, base_ipv4_address.split('.')))  # Convert to integers
        #print(f"Parsed IPv4 Parts: {base_ip_parts}")

        # Parse IPv6
        base_ipv6_parts = ipaddress.IPv6Address(base_ipv6_address).exploded.split(':')
        #print(f"Parsed IPv6 Parts: {base_ipv6_parts}")


        last_octet = int(request.form['last_octet'])
        base_vxlan_vni = int(request.form['base_vxlan_vni'])
        base_vxlan_vlan_id = int(request.form['base_vxlan_vlan_id'])
        num_vxlan_configs = int(request.form['num_vxlan_configs'])
        vxlan_filename = request.form['vxlan_filename']
        leaf_base_as = int(request.form['leaf_base_as'])
        spine_base_as = int(request.form['spine_base_as'])
        overlay_service_type = request.form['overlay_service_type']
        service_count = int(request.form['overlay_service_count'])

        # Get spine and leaf tags from the form
        spine_tags = [request.form.get(f'spine_tag_{i}') for i in range(1, num_spines + 1)]
        leaf_tags = [request.form.get(f'leaf_tag_{i}') for i in range(1, num_leafs + 1)]

        #print(f"self.spine_tags: {spine_tags}")
        #print(f"self.leaf_tags: {leaf_tags}")

        # Create an instance of the VxlanConfigGeneratorClass with separate IPv4 and IPv6 parts
        vxlan_generator = VxlanConfigGeneratorClass(
            spine_ips=spine_ips,
            leaf_ips=leaf_ips,
            base_ip_parts=base_ip_parts,  # Pass the IPv4 parts separately
            base_ipv6_parts=base_ipv6_parts,  # Pass the IPv6 parts separately
            last_octet=last_octet,
            base_vxlan_vni=base_vxlan_vni,
            base_vxlan_vlan_id=base_vxlan_vlan_id,
            num_vxlan_configs=num_vxlan_configs,
            overlay_service_type=overlay_service_type,
            leaf_base_as=leaf_base_as,
            spine_base_as=spine_base_as,
            service_count=service_count,
            service_int_leaves=service_int_leaves,
            esi_lag_services=esi_lag_services,
            leaf_tags=leaf_tags,
            spine_tags=spine_tags,
            GenerateOverlayBtn_State=GenerateOverlayBtn_State  # Pass the button state
        )

        # Generate the configurations for spines and leaves
        spine_configs, leaf_configs = vxlan_generator.generate_configs(spine_tags, leaf_tags)
        # Save spine configurations if available
        if spine_configs and len(spine_configs) > 0:
            for i, spine_config in enumerate(spine_configs):
                # Ensure filename is properly generated without concatenating prefixes repeatedly
                filename = f"spine_{i + 1}_{vxlan_filename}"
                config_file_path = os.path.join(current_app.config['DEVICE_CONFIG_FOLDER'], str(current_user.username),
                                                filename)
                filtered_config = [line for line in spine_config if not line.strip().startswith('#')]
                print(config_file_path)
                with open(config_file_path, "w") as config_file:
                    config_file.write("\n".join(filtered_config))

        # Save leaf configurations if available
        if leaf_configs and len(leaf_configs) > 0:
            for i, leaf_config in enumerate(leaf_configs):
                # Ensure filename is properly generated without concatenating prefixes repeatedly
                filename = f"leaf_{i + 1}_{vxlan_filename}"
                config_file_path = os.path.join(current_app.config['DEVICE_CONFIG_FOLDER'], str(current_user.username),
                                                filename)
                #print(config_file_path)
                # Filter out lines that start with '#'
                filtered_config = [line for line in leaf_config if not line.strip().startswith('#')]
                with open(config_file_path, "w") as config_file:
                    config_file.write("\n".join(filtered_config))
        download_link = True
        devices = get_router_details_from_db()
        #print(vxlan_filename)
        # Render the result page
        return render_template(
            'result_generate_vxlan_config.html',
            spine_configs=spine_configs,
            leaf_configs=leaf_configs,
            download_link=download_link,
            vxlan_filename=vxlan_filename,
            enumerate=enumerate,
            devices=devices
        )

    @app.route('/onboard_devices', methods=['GET', 'POST'])
    @login_required
    def onboard_devices():
        from sqlalchemy.exc import IntegrityError
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash('Please login again', 'error')
            return redirect(url_for('index'))

        if request.method == 'POST':
            if 'file' not in request.files:
                return jsonify({'success': False, 'error': 'No file part'}), 400
            file = request.files['file']

            if file.filename == '':
                return jsonify({'success': False, 'error': 'No selected file'}), 400
            if file:
                filename = file.filename
                if not filename.lower().endswith('.csv'):
                    return jsonify({'success': False, 'error': 'File is not a CSV'}), 400

                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                #   print(file_path)
                added_devices = []
                duplicated_devices = []
                conflicting_devices = []

                try:
                    # Fetch all devices used by other users
                    other_users_devices = DeviceInfo.query.filter(DeviceInfo.user_id != current_user.id).all()
                    other_user_ips = {device.ip: device.user_id for device in other_users_devices}
                    logging.info(f"Other users' devices: {list(other_user_ips.keys())}")

                    with open(file_path, 'r') as csvfile:
                        csvreader = csv.DictReader(csvfile)
                        expected_keys = {'hostname', 'ip', 'username', 'password'}

                        # Verify if all expected keys are in the CSV
                        if not expected_keys.issubset(csvreader.fieldnames):
                            missing_keys = expected_keys - set(csvreader.fieldnames)
                            logging.error(f"Missing keys in CSV: {missing_keys}")
                            return jsonify({'success': False, 'error': f'Missing keys in CSV: {missing_keys}'}), 400

                        with db.session.no_autoflush:
                            for row in csvreader:
                                # Log the row data for debugging
                                logging.info(f"Processing row: {row}")

                                # Check if row has all necessary keys
                                if not all(key in row for key in expected_keys):
                                    logging.error(f"Row is missing required keys: {row}")
                                    return jsonify({'success': False, 'error': f'Invalid row format: {row}'}), 400

                                # Check for existing devices for the current user
                                existing_device = DeviceInfo.query.filter_by(user_id=current_user.id,
                                                                             ip=row['ip']).first()
                                if existing_device:
                                    logging.info(f"Duplicate device found for user: {row['ip']}")
                                    duplicated_devices.append(row['ip'])
                                    continue

                                # Check if the IP is used by another user
                                if row['ip'] in other_user_ips:
                                    conflicting_user_id = other_user_ips[row['ip']]
                                    conflicting_user = User.query.get(conflicting_user_id)
                                    conflicting_devices.append({
                                        'ip': row['ip'],
                                        'conflicting_user': conflicting_user.username if conflicting_user else 'Unknown'
                                    })
                                    logging.info(
                                        f"IP conflict with user '{conflicting_user.username}' for IP: {row['ip']}")
                                    continue

                                # Add new device if it's unique for the current user
                                new_device = DeviceInfo(
                                    user_id=current_user.id,
                                    hostname=row['hostname'],
                                    ip=row['ip'],
                                    username=row['username'],
                                    password=row['password']
                                )
                                db.session.add(new_device)
                                added_devices.append(new_device.hostname)

                        if added_devices:
                            db.session.commit()  # Commit only if there are devices to add
                            logging.info(f"Added devices: {added_devices}")
                        else:
                            db.session.rollback()  # Rollback if no devices were added
                            logging.info("No devices added due to conflicts.")

                except IntegrityError as e:
                    db.session.rollback()
                    error_message = str(e.orig) if hasattr(e, 'orig') else str(e)
                    logging.error(f"IntegrityError: {error_message}")
                    return jsonify({'success': False, 'error': f'Database error: {error_message}'}), 400
                except Exception as e:
                    db.session.rollback()
                    logging.error(f"Error processing CSV: {str(e)}")
                    return jsonify({'success': False, 'error': f'Error processing CSV: {str(e)}'}), 400

                # Construct the appropriate response
                if added_devices or duplicated_devices or conflicting_devices:
                    return jsonify({
                        'success': True,
                        'message': 'Devices onboarded successfully.',
                        'added_devices': added_devices,
                        'duplicated_devices': duplicated_devices,
                        'conflicting_devices': conflicting_devices
                    }), 200
                else:
                    return jsonify({'success': False, 'message': 'No devices were added.'}), 400
        return redirect(url_for('index'))

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

    @app.route('/delete_device/<string:device_hostname>', methods=['POST'])
    @login_required
    def delete_device(device_hostname):
        # Find the device by hostname and current user's ID
        device = DeviceInfo.query.filter_by(hostname=device_hostname, user_id=current_user.id).first()
        if device:
            db.session.delete(device)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Device deleted successfully'})
        return jsonify({'success': False, 'message': 'Device not found'}), 404

    '''@app.route('/download/<filename>', methods=['GET'])
    @login_required
    def download(filename):
        # telemetry_folder = current_app.config['TELEMETRY_FOLDER']
        config_dir = os.path.abspath(current_app.config['UPLOAD_FOLDER'])
        # Assume telemetry_folder already includes the username
        config_file_path = os.path.join(config_dir, filename)
        #config_file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        logging.info(f"download: {config_file_path}")
        return send_file(config_file_path, as_attachment=True)'''

    @app.route('/download/<filename>')
    @login_required
    def download(filename):
        # Construct the user-specific folder path
        user_folder = os.path.join(current_app.config['DEVICE_CONFIG_FOLDER'], str(current_user.username))

        # Ensure the file exists in the user's folder
        if not os.path.exists(os.path.join(user_folder, filename)):
            return "File not found", 404

        # Send the file for download
        return send_from_directory(user_folder, filename, as_attachment=True)

