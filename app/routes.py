#routes.py#
from app import login_manager, socketio
from .models import DeviceInfo,TriggerEvent,TrainingData,Topology
from .utils import check_link_health, OnboardDeviceClass,get_router_details_from_db,transfer_file_to_router,generate_config,check_device_health,generate_bgp_scale_config,generate_vlan_config
from .utils import DeviceConnectorClass, BuildLLDPConnectionClass, VxlanConfigGeneratorClass,RobotXMLParserClass
from .utils import is_reachable, get_router_ips_from_csv,get_router_details_from_csv,get_lldp_neighbors,get_next_available_ip,generate_common_config,generate_interface_config,generate_bgp_config
from app.config import config
from app.models import User
from . import db
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, current_app, jsonify, send_from_directory,abort,make_response
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
import json, gzip



#print(f"current_app.config:: {current_app.config}")

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



    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        # Reset LOG_FOLDER to default when user logs out
        current_app.config['LOG_FOLDER'] = os.path.join(current_app.config['BASE_DIR'], 'logs')
        flash('You have been logged out.', 'success')
        return redirect(url_for('index'))


    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)  # Log in the user
                # Set up user-specific folders and logging
                config_class_name = os.getenv('FLASK_CONFIG') or 'development'
                config_class = config[config_class_name]()
                user_folder, log_folder, telemetry_folder, device_config = config_class.create_user_folders(username)
                # Update app configuration with user-specific folders
                current_app.config['UPLOAD_FOLDER'] = user_folder
                current_app.config['LOG_FOLDER'] = log_folder
                current_app.config['TELEMETRY_FOLDER'] = telemetry_folder
                current_app.config['DEVICE_FOLDER'] = device_config
                # Set up user-specific logging and obtain the logger
                config_class.setup_logging(log_folder)
                print(f"User-specific log folder set up at: {log_folder}")
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


    ### XML Robot Debugger ####
    @app.route('/xml_robot_debugger')
    def xml_robot_debugger():
        return render_template('xmlRobot_debugger.html')


    @app.route('/api/uploadRobotDebugFile', methods=['POST'])
    def upload_robot_debug_file():
        """
        Route for uploading and processing Robot Framework debug files.
        """
        try:
            # Initialize parser
            parser = RobotXMLParserClass(upload_folder=current_app.config['UPLOAD_FOLDER'])

            # Check if the file is part of the request
            if 'file' not in request.files:
                current_app.logger.error("No file part in the request.")
                return jsonify({"status": "error", "message": "No file part in the request"}), 400

            file = request.files['file']
            if file.filename == '':
                current_app.logger.error("No file selected for upload.")
                return jsonify({"status": "error", "message": "No file selected for upload"}), 400

            if not parser.allowed_file(file.filename):
                current_app.logger.error(f"Unsupported file type: {file.filename}")
                return jsonify({"status": "error", "message": "Unsupported file type"}), 400

            # Retrieve nameSuggestions flag
            name_suggestions = request.form.get('nameSuggestions', 'true').lower() == 'true'
            current_app.logger.info(f"nameSuggestions flag: {name_suggestions}")

            username = current_user.username
            user_id = current_user.id

            # Save file to user-specific folder
            file_path = parser.save_file(file, username)

            # Handle .gz files
            if file_path.endswith('.gz'):
                decompressed_file_path = file_path[:-3]  # Remove '.gz' extension
                try:
                    with gzip.open(file_path, 'rb') as gz_file:
                        with open(decompressed_file_path, 'wb') as out_file:
                            out_file.write(gz_file.read())
                    os.remove(file_path)  # Remove the original .gz file
                    file_path = decompressed_file_path
                    current_app.logger.info(f"Decompressed .gz file to: {file_path}")
                except Exception as e:
                    current_app.logger.error(f"Error decompressing .gz file: {e}", exc_info=True)
                    return jsonify({"status": "error", "message": "Error decompressing .gz file"}), 500

            # Read XML content
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    xml_content = f.read()
            except Exception as e:
                current_app.logger.error(f"Error reading file {file_path}: {e}", exc_info=True)
                return jsonify({"status": "error", "message": "Error reading file"}), 500

            # Parse failures from the XML content
            failures = parser.parse_robot_xml(xml_content=xml_content)

            # Save failures to a log file
            log_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], username, "robot_failure_logs")
            os.makedirs(log_dir, exist_ok=True)
            failure_log_path = os.path.join(log_dir, f"{file.filename}_failure_log.txt")
            try:
                with open(failure_log_path, 'w', encoding='utf-8') as log_file:
                    log_file.write(failures)
            except Exception as e:
                current_app.logger.error(f"Error writing failure log: {e}", exc_info=True)
                return jsonify({"status": "error", "message": "Error saving failure log"}), 500

            suggestions = None
            unmatched_message = None

            if name_suggestions:
                try:
                    # Query TrainingData from the database
                    training_data = TrainingData.query.filter_by(user_id=user_id).all()

                    # Display corrective actions
                    unmatched_message = parser.display_corrective_actions_from_file(
                        failure_log_path, training_data, user_id, log_dir
                    )

                    # Read the generated suggestions
                    suggestions_file_path = os.path.join(log_dir, "robot_failure_suggestions.txt")
                    if os.path.exists(suggestions_file_path):
                        with open(suggestions_file_path, 'r', encoding='utf-8') as suggestion_file:
                            suggestions = suggestion_file.read()
                except ValueError as ve:
                    unmatched_message = str(ve)
                    current_app.logger.warning(f"ValueError during corrective actions: {ve}")
                except Exception as e:
                    unmatched_message = "An error occurred while generating suggestions."
                    current_app.logger.error(f"Error during corrective actions: {e}", exc_info=True)

            # Clean up uploaded file
            os.remove(file_path)

            # Prepare response data
            response_data = {
                "status": "success",
                "message": "File uploaded and parsed successfully",
                "failures": failures,
                "filename": file.filename,  # Track filename in the response
            }

            if name_suggestions and suggestions:
                response_data["suggestions"] = suggestions

            if unmatched_message:
                response_data["unmatched_message"] = unmatched_message

            current_app.logger.info("Upload and processing completed successfully.")
            return jsonify(response_data), 200

        except ValueError as ve:
            current_app.logger.error(f"ValueError: {ve}")
            return jsonify({"status": "error", "message": str(ve)}), 400
        except Exception as e:
            current_app.logger.error(f"Exception: {e}", exc_info=True)
            return jsonify({"status": "error", "message": "An unexpected error occurred."}), 500

    @app.route('/fetchXML', methods=['POST'])
    def fetch_xml():
        """
        Route for fetching XML from a URL and parsing it.
        """
        from utils import RobotLogParser
        import requests
        from io import BytesIO

        parser = RobotLogParser(current_app.config['UPLOAD_FOLDER'])
        data = request.json

        url = data.get('url')
        jsessionid = data.get('jsessionid')

        if not url:
            return jsonify({"status": "error", "message": "URL is required"}), 400

        try:
            # Fetch the XML content
            headers = {"User-Agent": "Mozilla/5.0"}
            cookies = {"JSESSIONID": jsessionid} if jsessionid else None
            response = requests.get(url, headers=headers, cookies=cookies)

            if response.status_code != 200:
                return jsonify({"status": "error", "message": "Failed to fetch XML"}), response.status_code

            tree = ET.parse(BytesIO(response.content))
            failures = parser.parse_robot_xml(tree=tree)

            return jsonify({
                "status": "success",
                "message": "XML fetched and parsed successfully",
                "failures": failures
            }), 200
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500


    @app.route('/api/downloadTrainingData', methods=['GET'])
    @login_required  # Ensure the user is logged in
    def download_training_data():
        """
        Route to allow downloading training data in JSON format. Only admin-saved data is allowed.
        """
        try:
            # Assuming admin has a specific user_id (e.g., 1) or role
            admin_user_id = 1  # Replace with the actual ID or role check for the admin user

            # Query training data saved by the admin
            training_data = TrainingData.query.filter_by(user_id=admin_user_id).all()

            # Prepare data for download in the desired format
            data = {}
            for td in training_data:
                if td.category not in data:
                    data[td.category] = {}
                data[td.category][td.pattern] = td.suggestion

            # Create a JSON response
            response = make_response(json.dumps(data, indent=4))
            response.headers['Content-Type'] = 'application/json'
            response.headers['Content-Disposition'] = 'attachment; filename=training_data.json'

            return response

        except Exception as e:
            current_app.logger.error(f"Error while preparing training data for download: {e}")
            return jsonify({"status": "error", "message": "Unable to download training data."}), 500

    @app.route('/getCategories', methods=['GET'])
    def get_categories():
        try:
            # Query distinct categories from the TrainingData table
            categories = TrainingData.query.with_entities(TrainingData.category).distinct().all()
            # Extract category names from the query result
            category_list = [category[0] for category in categories]
            return jsonify({"categories": category_list}), 200

        except Exception as e:
            # Log the error for debugging
            print(f"Error loading categories: {e}")
            return jsonify({"message": f"Failed to load categories: {str(e)}"}), 500

    @app.route('/getTrainingData', methods=['GET'])
    @login_required
    def get_training_data():
        category = request.args.get('category')
        if not category:
            return jsonify({"message": "Category is required."}), 400

        try:
            training_data = TrainingData.query.filter_by(user_id=current_user.id, category=category).all()
            result = [
                {"pattern": data.pattern, "suggestion": data.suggestion}
                for data in training_data
            ]
            return jsonify(result), 200
        except Exception as e:
            return jsonify({"message": f"Failed to fetch training data: {str(e)}"}), 500


    @app.route('/uploadJsonTrainingFile', methods=['POST'])
    def uploadJsonTrainingFile():
        if 'file' not in request.files:
            return jsonify({"message": "No file part"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"message": "No selected file"}), 400
        if file and file.filename.endswith('.json'):
            try:
                # Parse the JSON data from the file
                data = json.load(file)

                # Assuming JSON structure is { "Category": { "Pattern": "Suggestion", ... }, ... }
                for category, patterns in data.items():
                    if not isinstance(patterns, dict):
                        return jsonify({"message": f"Invalid structure for category '{category}'"}), 400

                    for pattern, suggestion in patterns.items():
                        # Validate fields
                        if not pattern or not suggestion:
                            return jsonify({"message": f"Pattern or suggestion missing for category '{category}'"}), 400

                        # Check for duplicates
                        existing_entry = TrainingData.query.filter_by(user_id=current_user.id, pattern=pattern).first()
                        if existing_entry:
                            # Optionally, update the suggestion for existing patterns
                            existing_entry.suggestion = suggestion
                        else:
                            # Add a new entry to the database
                            new_entry = TrainingData(
                                user_id=current_user.id,  # Assumes user is authenticated
                                category=category,
                                pattern=pattern,
                                suggestion=suggestion
                            )
                            db.session.add(new_entry)
                # Commit the changes
                db.session.commit()
                return jsonify({"message": "Data loaded successfully"}), 200
            except json.JSONDecodeError:
                return jsonify({"message": "Invalid JSON format"}), 400
            except Exception as e:
                db.session.rollback()
                return jsonify({"message": f"Failed to load data: {str(e)}"}), 500
        return jsonify({"message": "Unsupported file type"}), 400

    # Route for direct text submission
    @app.route('/addPattern', methods=['POST'])
    @login_required
    def add_pattern():
        data = request.get_json()
        category = data.get('category')
        pattern = data.get('pattern')
        suggestion = data.get('suggestion')
        if not category or not pattern or not suggestion:
            return jsonify({"message": "All fields are required."}), 400
        if TrainingData.query.filter_by(pattern=pattern, user_id=current_user.id).first():
            return jsonify({"message": "Pattern already exists."}), 400
        new_entry = TrainingData(
            user_id=current_user.id,
            category=category,
            pattern=pattern,
            suggestion=suggestion
        )
        db.session.add(new_entry)
        db.session.commit()
        return jsonify({"message": "New pattern added successfully."})
    @app.route('/getCategoriesAndPatterns', methods=['GET'])
    def get_categories_and_patterns():
        categories = TrainingData.query.with_entities(TrainingData.category.distinct()).all()
        return jsonify({"categories": [c[0] for c in categories]})

    @app.route('/getPatterns', methods=['GET'])
    def get_patterns():
        category = request.args.get('category')
        if not category:
            return jsonify({"patterns": []}), 400
        patterns = TrainingData.query.filter_by(category=category, user_id=current_user.id).with_entities(
            TrainingData.pattern).all()
        return jsonify({"patterns": [p[0] for p in patterns]})

    @app.route('/getSuggestion', methods=['GET'])
    def get_suggestion():
        pattern = request.args.get('pattern')
        if not pattern:
            return jsonify({"suggestion": ""}), 400
        suggestion = TrainingData.query.filter_by(pattern=pattern, user_id=current_user.id).with_entities(
            TrainingData.suggestion).first()
        return jsonify({"suggestion": suggestion[0] if suggestion else ""})

    @app.route('/updatePattern', methods=['POST'])
    def update_pattern():
        data = request.get_json()
        pattern = data.get('pattern')
        suggestion = data.get('suggestion')
        if not pattern or not suggestion:
            return jsonify({"message": "Pattern and suggestion are required."}), 400
        record = TrainingData.query.filter_by(pattern=pattern, user_id=current_user.id).first()
        if not record:
            return jsonify({"message": "Pattern not found."}), 404
        record.suggestion = suggestion
        db.session.commit()
        return jsonify({"message": "Pattern updated successfully."})

    @app.route('/deletePattern', methods=['POST'])
    @login_required
    def delete_pattern():
        try:
            data = request.get_json()
            pattern = data.get('pattern')
            if not pattern:
                return jsonify({"message": "Pattern is required."}), 400

            # Find and delete the pattern
            record = TrainingData.query.filter_by(pattern=pattern, user_id=current_user.id).first()
            if not record:
                return jsonify({"message": "Pattern not found."}), 404

            db.session.delete(record)
            db.session.commit()
            return jsonify({"message": "Pattern deleted successfully."}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"message": f"Failed to delete pattern: {str(e)}"}), 500




    ### XML Robot Parser END ###


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
    def check_device_health_route():
        def remove_none_values(d):
            """Recursively remove None values from dictionaries or lists."""
            if isinstance(d, dict):
                return {k: remove_none_values(v) for k, v in d.items() if k is not None and v is not None}
            elif isinstance(d, list):
                return [remove_none_values(item) for item in d if item is not None]
            else:
                return d
        data = request.get_json()
        devices = data.get('devices', [])

        try:
            router_details = get_router_details_from_db()
            device_health_status = check_device_health(router_details, devices)
            cleaned_device_health_status = remove_none_values(device_health_status)
        except Exception as e:
            logging.error(f"Error in device health check: {e}", exc_info=True)
            return jsonify({"error": "Server error during device health check"}), 500

        return jsonify({
            'device_health_status': cleaned_device_health_status
        })

    @app.route('/check_link_health', methods=['POST'])
    @login_required
    def check_link_health_route():
        def remove_none_values(d):
            """Recursively remove None values from dictionaries or lists."""
            if isinstance(d, dict):
                return {k: remove_none_values(v) for k, v in d.items() if k is not None and v is not None}
            elif isinstance(d, list):
                return [remove_none_values(item) for item in d if item is not None]
            else:
                return d
        data = request.get_json()
        edges = data.get('edges', [])
        try:
            router_details = get_router_details_from_db()
            link_health_status = check_link_health(router_details, edges)
            cleaned_link_health_status = remove_none_values(link_health_status)
        except Exception as e:
            logging.error(f"Error in link health check: {e}", exc_info=True)
            return jsonify({"error": "Server error during link health check"}), 500

        return jsonify({
            'link_health_status': cleaned_link_health_status
        })

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

    @app.route('/view_underlay_csv_config', methods=['GET'])
    @login_required
    def view_underlay_csv_config():
        # Define the path to the user-specific commands file for CSV config
        user_folder = os.path.join(current_app.config['DEVICE_CONFIG_FOLDER'], str(current_user.username))
        commands_file = os.path.join(user_folder, 'commands_csv.json')

        # Check if the commands file exists
        if os.path.exists(commands_file):
            with open(commands_file, 'r') as f:
                commands = json.load(f)
        else:
            flash('No configuration data available. Please generate it first.', 'error')
            return redirect(url_for('index'))

        devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
        return render_template('underlay_config_result.html', commands=commands, devices=devices)

    @app.route('/view_underlay_lldp_config', methods=['GET'])
    @login_required
    def view_underlay_lldp_config():
        def normalize_hostname(hostname):
            """Remove the domain suffix from the hostname if it exists."""
            return hostname.split('.')[0]  # Only keep the part before the first dot
        # Define the path to the user-specific commands file for LLDP config
        user_folder = os.path.join(current_app.config['DEVICE_CONFIG_FOLDER'], str(current_user.username))
        commands_file = os.path.join(user_folder, 'commands_lldp.json')
        # Check if the commands file exists
        if os.path.exists(commands_file):
            with open(commands_file, 'r') as f:
                commands = json.load(f)
            # Normalize hostnames in the commands data
            normalized_commands = {normalize_hostname(host): cmds for host, cmds in commands.items()}
        else:
            flash('No LLDP configuration data available. Please generate it first.', 'error')
            return redirect(url_for('index'))

        # Retrieve devices from the database and normalize their hostnames
        devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
        normalized_devices = [{**device.__dict__, 'hostname': normalize_hostname(device.hostname)} for device in
                              devices]

        return render_template('underlay_config_result.html', commands=normalized_commands, devices=normalized_devices)

    @app.route('/show_underlay_lldp_config', methods=['POST'])
    @login_required
    def show_underlay_lldp_config():
        def normalize_hostname(hostname):
            """Remove the domain suffix from the hostname, if it exists."""
            return hostname.split('.')[0]
        try:
            if not current_user.is_authenticated:
                flash('Please login again', 'error')
                return jsonify({'success': False, 'error': 'Please login again'}), 401

            # Existing config flags
            config_method = request.form.get('config_method')
            delete_underlay_group = request.form.get('delete_group') == "on"
            use_ipv4 = request.form.get('ipv4_underlay') == "on"
            use_ipv6 = request.form.get('ipv6_underlay') == "on"
            selected_load_balancer = request.form.get('load_balancer')
            use_dlb = selected_load_balancer == "dlb"
            use_glb = selected_load_balancer == "glb"
            use_slb = selected_load_balancer == "slb"
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

            # Normalize device hostnames and prepare the local AS mapping
            for device in devices:
                if device and device.hostname:
                    device_name = normalize_hostname(device.hostname.strip())
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
                #device_name = normalize_hostname(device.hostname.strip()) if device and device.hostname else None
                device_name = device.hostname.strip() if device and device.hostname else None
                if not device_name:
                    logging.error(f"Skipping device with undefined hostname at index {index}")
                    continue
                try:
                    dev_connector = DeviceConnectorClass(device_name, device.ip, device.username, device.password)
                    dev = dev_connector.connect_to_device()
                    logging.info(f"Connected to {device_name}")

                    # Fetch LLDP neighbors
                    lldp_builder = BuildLLDPConnectionClass(device_name, device_list)
                    neighbors = lldp_builder.get_lldp_neighbors(dev)

                    current_progress += progress_increment // 3
                    socketio.emit('overall_progress', {
                        'device': device_name,
                        'progress': current_progress,
                        'stage': 'simplified_neighbors'
                    })

                    # Normalize neighbors and update neighbors_dict
                    for host, data in neighbors.items():
                        normalized_host = normalize_hostname(host)
                        neighbors_dict[normalized_host].extend(data)
                    success_hosts.append(device_name)

                    simplified_neighbors = lldp_builder.simplify_neighbors_dict(neighbors_dict)

                    current_progress += progress_increment // 3
                    socketio.emit('overall_progress', {
                        'device': device_name,
                        'progress': current_progress,
                        'stage': 'lldp_builder'
                    })

                    # Normalize connections
                    connections = [
                        {normalize_hostname(device): interface for device, interface in conn.items()}
                        for conn in lldp_builder.build_connections(simplified_neighbors)
                    ]
                    #logging.warning(connections)
                    generate_config(commands, connections, local_as_mapping, delete_underlay_group, use_ipv4, use_ipv6,
                                    use_dlb, use_glb, use_slb, ip_assignments)
                    current_progress += progress_increment // 3
                    socketio.emit('overall_progress', {
                        'device': device_name,
                        'progress': current_progress,
                        'stage': 'generate_config'
                    })

                except (ConnectAuthError, ConnectUnknownHostError, SSHError, paramiko.SSHException, socket.error,
                        ConnectionResetError) as e:
                    error_message = f"Connection failed: {str(e)}"
                    failed_hosts.add((device_name, error_message))
                    socketio.emit('overall_progress', {
                        'device': device_name,
                        'progress': current_progress,
                        'stage': 'Error',
                        'fail': error_message
                    })
                    logging.error(f"Connection error for device {device_name}: {str(e)}")
                    continue

                except Exception as e:
                    error_message = f"Unexpected error: {str(e)}"
                    failed_hosts.add((device_name, error_message))
                    socketio.emit('overall_progress', {
                        'device': device_name,
                        'progress': current_progress,
                        'stage': 'Error',
                        'fail': error_message
                    })
                    logging.error(f"Unexpected error during LLDP configuration for device {device_name}: {str(e)}")
                    continue

            # Save commands to user-specific JSON file
            user_folder = os.path.join(current_app.config['DEVICE_CONFIG_FOLDER'], str(current_user.username))
            os.makedirs(user_folder, exist_ok=True)
            # Save each device's configuration to a JSON file
            for hostname, cmds in commands.items():
                config_filename = f"{hostname}_config.txt"
                config_filepath = os.path.join(user_folder, config_filename)
                with open(config_filepath, 'w') as config_file:
                    config_file.write("\n".join(cmds))
            commands_file = os.path.join(user_folder, 'commands_lldp.json')

            with open(commands_file, 'w') as f:
                json.dump(commands, f)

            final_message = "Configuration complete with some errors" if failed_hosts else "Configuration completed successfully"

            # Emit final progress update to report status
            socketio.emit('overall_progress', {
                'progress': 100,
                'stage': 'Completed',
                'message': final_message,
                'failed_hosts': list(failed_hosts),
                'success_hosts': success_hosts
            })

            return jsonify({'status': 'Configuration completed successfully'}), 200

        except Exception as main_error:
            error_traceback = traceback.format_exc()
            logging.error(f"Unexpected error during LLDP configuration: {error_traceback}")

            # Emit detailed error message via socket
            socketio.emit('overall_progress', {
                'progress': 0,
                'stage': 'Error',
                'fail': f"Unexpected error: {error_traceback}"
            })

            return jsonify({'error': 'Unexpected error occurred.'}), 500

    @app.route('/show_underlay_csv_config', methods=['POST'])
    @login_required
    def show_underlay_csv_config():
        csv_file = request.files.get('csv_file')
        delete_underlay_group = request.form.get('delete_group') == "on"
        use_ipv4 = request.form.get('ipv4_underlay') == "on"
        use_ipv6 = request.form.get('ipv6_underlay') == "on"
        selected_load_balancer = request.form.get('load_balancer')
        use_dlb = selected_load_balancer == "dlb"
        use_glb = selected_load_balancer == "glb"
        use_slb = selected_load_balancer == "slb"
        as_counter = 65000
        unique_devices = set()
        # Check if file is uploaded
        if not csv_file or csv_file.filename == '':
            return jsonify({'error': 'No file selected. Please upload a CSV file.'}), 400
        # Check file format
        if not csv_file.filename.endswith('.csv'):
            return jsonify({'error': 'Invalid file format. Please upload a CSV file.'}), 400
        # Save the file
        filename = secure_filename(csv_file.filename)
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        csv_file.save(filepath)

        try:
            with open(filepath, mode='r') as file:
                csv_reader = csv.DictReader(file)
                connections = []
                local_as_mapping = {}
                seen = set()
                duplicates = []
                duplicate_device_interfaces = []

                # Track rows processed for progress calculation
                row_count = sum(1 for _ in csv_reader)
                file.seek(0)  # Reset file read position
                progress_increment = 100 // row_count if row_count > 0 else 0
                current_progress = 0

                for row in csv_reader:
                    # Skip rows where device names are headers or placeholders ("device1", "device2")
                    if row['device1'].strip().lower() in {'device1', 'device2'} or row['device2'].strip().lower() in {
                        'device1', 'device2'}:
                        continue  # Skip this row

                    # Track unique devices
                    unique_devices.add(row['device1'])
                    unique_devices.add(row['device2'])

                    # Verify expected keys are present
                    if not {'device1', 'interface1', 'device2', 'interface2'}.issubset(row.keys()):
                        return jsonify({'error': 'CSV file format is incorrect. Missing required headers.'}), 400

                    # Create tuples for both sides of the connection
                    connection_tuple_1 = (row['device1'], row['interface1'])
                    connection_tuple_2 = (row['device2'], row['interface2'])

                    # Check for duplicates
                    if connection_tuple_1 in seen or connection_tuple_2 in seen:
                        duplicates.append({row['device1']: row['interface1'], row['device2']: row['interface2']})
                        if connection_tuple_1 in seen:
                            duplicate_device_interfaces.append(
                                f"Duplicate device/interface found: {row['device1']} using {row['interface1']}")
                        if connection_tuple_2 in seen:
                            duplicate_device_interfaces.append(
                                f"Duplicate device/interface found: {row['device2']} using {row['interface2']}")
                    else:
                        # Add unique connections
                        seen.add(connection_tuple_1)
                        seen.add(connection_tuple_2)
                        connections.append({row['device1']: row['interface1'], row['device2']: row['interface2']})

                    # Emit real-time progress update
                    current_progress += progress_increment
                    socketio.emit('overall_progress', {
                        'progress': min(current_progress, 100),
                        'stage': 'Processing CSV',
                        'message': 'Parsing connections'
                    })

                if duplicates:
                    return jsonify({
                        'error': 'Duplicate data found: same device/interface used multiple times.',
                        'duplicates': duplicates,
                        'duplicate_interfaces': duplicate_device_interfaces
                    }), 400

                devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
                if not devices:
                    return jsonify({'error': f"No devices found for user {current_user.id}"}), 400

                # Map AS numbers to devices
                for device in devices:
                    if device.hostname not in local_as_mapping:
                        local_as_mapping[device.hostname] = as_counter
                        as_counter += 1

                # Generate configuration based on CSV data
                commands = defaultdict(list)

                generate_config(commands, connections, local_as_mapping, delete_underlay_group, use_ipv4, use_ipv6,use_dlb, use_glb,use_slb)

                # Remove any configurations generated for placeholder names
                commands = {host: cmds for host, cmds in commands.items() if host not in {"device1", "device2"}}

                # Save each device's configuration to a JSON file
                user_folder = os.path.join(current_app.config['DEVICE_CONFIG_FOLDER'], str(current_user.username))
                os.makedirs(user_folder, exist_ok=True)
                for hostname, cmds in commands.items():
                    config_filename = f"{hostname}_config.txt"
                    config_filepath = os.path.join(user_folder, config_filename)
                    with open(config_filepath, 'w') as config_file:
                        config_file.write("\n".join(cmds))

                commands_file = os.path.join(user_folder, 'commands_csv.json')

                with open(commands_file, 'w') as f:
                    json.dump(commands, f)

                # Prepare the list of success messages
                success_hosts = [f"{device}: Success" for device in unique_devices if
                                 device not in {"device1", "device2"}]

                # Emit final progress update with success hosts
                socketio.emit('overall_progress', {
                    'progress': 100,
                    'stage': 'Completed',
                    'message': "Configuration completed successfully",
                    'success_hosts': success_hosts
                })

                return jsonify({'status': 'Configuration completed successfully'}), 200

        except csv.Error as e:
            logging.info(f"Error processing CSV file in function show_underlay_csv_config: {e}")
            return jsonify({'error': f"Error processing CSV file: {e}"}), 400

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
        unique_connections_set = set()

        if not devices:
            flash('No devices found for the current user.', 'error')
            return redirect(url_for('index'))

        total_devices = len(devices)
        progress_increment = 100 // total_devices
        current_progress = 0

        # Prepare the local AS mapping
        for device in devices:
            device_list.append(device.hostname)
            if device.hostname not in local_as_mapping:
                local_as_mapping[device.hostname] = as_counter
                as_counter += 1

        def strip_domain(hostname):
            """Strip the domain from a hostname."""
            return hostname.split('.')[0]

        # Process each device and collect unique connections
        for index, device in enumerate(devices):
            try:
                dev_connector = DeviceConnectorClass(device.hostname, device.ip, device.username, device.password)
                dev = dev_connector.connect_to_device()

                lldp_builder = BuildLLDPConnectionClass(device.hostname, device_list)
                neighbors = lldp_builder.get_lldp_neighbors(dev)
                logging.info(f"get_lldp_neighbors= {neighbors}")

                # Combine neighbors into the global dictionary
                for host, data in neighbors.items():
                    neighbors_dict[host].extend(data)
                success_hosts.append(device.hostname)

                # Simplify neighbors dict (remove domain from hostnames)
                simplified_neighbors = lldp_builder.simplify_neighbors_dict(neighbors_dict)
                connections = lldp_builder.build_connections(simplified_neighbors)

                for connection in connections:
                    # Remove domains and sort to create unique, domain-free connection tuples
                    stripped_connection = {strip_domain(k): v for k, v in connection.items()}
                    sorted_connection = tuple(sorted(stripped_connection.items()))

                    if sorted_connection not in unique_connections_set:
                        unique_connections_set.add(sorted_connection)
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

        # Generate CSV content
        for connection in unique_connections:
            keys = list(connection.keys())
            if len(keys) < 2:
                logging.warning(f"Skipping connection with only one device: {connection}")
                continue
            device1 = strip_domain(keys[0])
            device2 = strip_domain(keys[1])
            interface1 = connection[keys[0]]
            interface2 = connection[keys[1]]

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



    '''@app.route('/upload_config', methods=['GET', 'POST'])
    @login_required
    def upload_config():
        if request.method == 'POST':
            config_file = request.files.get('file')
            config_text = request.form.get('config_textarea')
            router_ips = request.form['router_ips'].split(',')  # IPs still provided in form
            # Query device information from the database based on the logged-in user
            devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
            device_credentials = {device.hostname: {'username': device.username, 'password': device.password} for device in
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
        return render_template('upload_config.html')'''

    '''@app.route('/upload_config', methods=['GET', 'POST'])
    @login_required
    def upload_config():
        if request.method == 'POST':
            config_file = request.files.get('file')
            config_text = request.form.get('config_textarea')
            router_ips = request.form['router_ips'].split(',')
            # Query device information from the database based on the logged-in user
            devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
            device_credentials = {
                device.hostname: {
                    'ip': device.ip,
                    'username': device.username,
                    'password': device.password
                } for device in devices
            }
            def is_operational_command(line):
                return line.strip().lower().startswith(("show", "clear"))
            def emit_progress(router_ip, progress, error=None):
                socketio.emit('progress', {'ip': router_ip, 'progress': progress, 'error': error}, namespace='/')
            def handle_device(router_ip, config_to_load, config_format, results, max_retries=3, retry_delay=5):
                if router_ip not in device_credentials:
                    emit_progress(router_ip, 0, error=f"Credentials not found for device {router_ip}")
                    results[router_ip] = {'success': False, 'message': f"Credentials not found for {router_ip}"}
                    return
                # Set up device connection using DeviceConnectorClass
                device_info = device_credentials[router_ip]
                connector = DeviceConnectorClass(
                    hostname=router_ip,
                    ip=device_info['ip'],
                    username=device_info['username'],
                    password=device_info['password']
                )
                attempt = 1
                while attempt <= max_retries:
                    try:
                        emit_progress(router_ip, 0)
                        dev = connector.connect_to_device()
                        if not dev:
                            raise ValueError("Device connection failed")
                        emit_progress(router_ip, 25)
                        cu = Config(dev)
                        cu.lock()
                        emit_progress(router_ip, 50)
                        cu.load(config_to_load, format=config_format, ignore_warning=True)
                        emit_progress(router_ip, 75)
                        cu.commit()
                        cu.unlock()
                        connector.close_connection(dev)
                        emit_progress(router_ip, 100)
                        results[router_ip] = {'success': True, 'message': 'Configuration loaded successfully'}
                        break  # Success, exit loop
                    except LockError:
                        emit_progress(router_ip, 0, error="Configuration database locked. Retrying after rollback...")
                        cu.rollback()  # Rollback to the previous state
                        cu.unlock()
                        if attempt < max_retries:
                            time.sleep(retry_delay)
                        else:
                            results[router_ip] = {'success': False,
                                                  'message': "Max retries reached. Could not lock config."}
                            emit_progress(router_ip, 0, error="Max retries reached. Could not lock config.")
                        attempt += 1
                    except (ConnectAuthError, ConnectError, ConfigLoadError, CommitError) as e:
                        emit_progress(router_ip, 0, error=str(e))
                        results[router_ip] = {'success': False, 'message': str(e)}
                        break
                    except Exception as e:
                        emit_progress(router_ip, 0, error=str(e))
                        results[router_ip] = {'success': False, 'message': str(e)}
                        break
                connector.close_connection(dev)
            if config_file:
                #config_file_path = os.path.join(app.config['UPLOAD_FOLDER'], config_file.filename)
                config_file_path = os.path.join(current_app.config['DEVICE_CONFIG_FOLDER'], str(current_user.username),filename)
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
            results = {}
            threads = []
            for router_ip in router_ips:
                thread = threading.Thread(target=handle_device,
                                          args=(router_ip.strip(), config_to_load, config_format, results))
                threads.append(thread)
                thread.start()
            for thread in threads:
                thread.join()
            success = all(result['success'] for result in results.values())
            return jsonify(success=success, results=results)
        return render_template('upload_config.html')'''

    @app.route('/upload_config', methods=['GET', 'POST'])
    @login_required
    def upload_config():
        if request.method == 'POST':
            config_file = request.files.get('file')
            config_text = request.form.get('config_textarea')
            router_ips = request.form['router_ips'].split(',')
            devices = DeviceInfo.query.filter_by(user_id=current_user.id).all()
            device_credentials = {device.hostname: {'username': device.username, 'password': device.password} for device
                                  in devices}

            def emit_progress(router_ip, progress, error=None):
                socketio.emit('progress', {'ip': router_ip, 'progress': progress, 'error': error}, namespace='/')

            def handle_device(router_ip, config_commands, operational_commands, config_format, results, max_retries=3,
                              retry_delay=5):
                attempt = 1
                while attempt <= max_retries:
                    try:
                        emit_progress(router_ip, 0)
                        if router_ip not in device_credentials:
                            raise ValueError(f"Credentials not found for device {router_ip}")
                        router_user = device_credentials[router_ip]['username']
                        router_password = device_credentials[router_ip]['password']

                        connector = DeviceConnectorClass(router_ip, router_ip, router_user, router_password)
                        dev = connector.connect_to_device()
                        if dev is None:
                            raise ConnectError(f"Failed to connect to {router_ip}")

                        # Execute operational commands
                        for command in operational_commands:
                            result = dev.rpc.cli(command, format='text')
                            logging.info(f"Operational Command Result on {router_ip}: {result}")

                        # If there are config commands, handle configuration
                        if config_commands:
                            emit_progress(router_ip, 25)
                            cu = Config(dev)
                            cu.lock()
                            emit_progress(router_ip, 50)
                            cu.load("\n".join(config_commands), format=config_format, ignore_warning=True)
                            emit_progress(router_ip, 75)
                            cu.commit()
                            cu.unlock()

                        connector.close_connection(dev)
                        emit_progress(router_ip, 100)
                        results[router_ip] = {'success': True,
                                              'message': 'Configuration and operational commands executed successfully'}
                        break

                    except LockError as e:
                        logging.warning(
                            f"LockError on {router_ip}. Retrying after rollback (Attempt {attempt}/{max_retries})")
                        emit_progress(router_ip, 0, error="Configuration database locked. Retrying after rollback...")
                        try:
                            cu.rollback()
                            cu.unlock()
                        except UnlockError:
                            logging.warning(f"UnlockError on {router_ip}. Could not unlock after rollback.")
                        except Exception as rollback_error:
                            logging.error(f"Error during rollback on {router_ip}: {str(rollback_error)}")
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

            def is_operational_command(line):
                return line.strip().lower().startswith(("show", "clear"))

            if config_file:
                config_file_path = os.path.join(app.config['UPLOAD_FOLDER'], config_file.filename)
                config_file.save(config_file_path)
                with open(config_file_path, 'r') as file:
                    config_lines = file.readlines()
            elif config_text:
                config_lines = config_text.splitlines()
            else:
                return 'No configuration provided', 400

            # Separate operational and configuration commands
            clean_config_lines = [line for line in config_lines if line.strip() and not line.startswith("#")]
            config_commands = [line for line in clean_config_lines if not is_operational_command(line)]
            operational_commands = [line for line in clean_config_lines if is_operational_command(line)]
            config_format = 'set' if any(line.startswith(("set", "delete")) for line in config_commands) else 'text'

            results = {}
            threads = []
            print(config_commands)
            print(operational_commands)
            for router_ip in router_ips:
                thread = threading.Thread(target=handle_device,
                                args=(router_ip.strip(), config_commands, operational_commands, config_format, results))
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

    '''@app.route('/transfer', methods=['POST'])
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
        return jsonify(response)'''

    @app.route('/transfer', methods=['POST'])
    @login_required
    def transfer():
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash('Please login again', 'error')
            return redirect(url_for('index'))

        filename = request.form['filename']
        router_ip = request.form['router_ip']
        device_name = None

        # Fetch device details from the database
        devices = get_router_details_from_db()
        for device in devices:
            if device['ip'] == router_ip:
                router_user = device['username']
                router_password = device['password']
                device_name = device['hostname']
                break

        config_file_path = os.path.join(current_app.config['DEVICE_CONFIG_FOLDER'], str(current_user.username),
                                        filename)
        try:
            with open(config_file_path, 'r') as config_file:
                config_lines = config_file.readlines()

            config_format = "set"

            # Emit progress: Transfer started
            socketio.emit('transfer_progress', {
                'hostname': device_name,
                'progress': 10,
                'message': f"Starting transfer to {device_name} ({router_ip})..."
            })

            # Simulate transfer process
            transfer_status = transfer_file_to_router(config_lines, router_ip, router_user, router_password,
                                                      device_name, config_format)

            # Emit progress: Transfer in progress
            socketio.emit('transfer_progress', {
                'hostname': device_name,
                'progress': 70,
                'message': f"Transferring configuration to {device_name}..."
            })

            # Check transfer status and emit final progress
            if 'successfully' in transfer_status:
                socketio.emit('transfer_progress', {
                    'hostname': device_name,
                    'progress': 100,
                    'message': f"Transfer to {device_name} completed successfully!",
                    'status': 'success'
                })
                response = {
                    'success': True,
                    'message': transfer_status
                }
            else:
                socketio.emit('transfer_progress', {
                    'hostname': device_name,
                    'progress': 100,
                    'message': f"Transfer to {device_name} failed: {transfer_status}",
                    'status': 'failure'
                })
                response = {
                    'success': False,
                    'message': transfer_status
                }
        except Exception as e:
            # Emit progress: Transfer error
            socketio.emit('transfer_progress', {
                'hostname': device_name,
                'progress': 100,
                'message': f"Error transferring to {device_name}: {str(e)}",
                'status': 'error'
            })
            response = {
                'success': False,
                'message': str(e)
            }
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

