#run.py#
from app import create_app
import os
import logging
from flask_session import Session  # ✅ Ensure flask-session is installed



# Select environment configuration
config_name = os.getenv('FLASK_CONFIG') or 'development'
app = create_app(config_name)

# Set Flask session storage type
app.config['SECRET_KEY'] = 'your_strong_secret_key_here'  # Ensure a secret key is set
app.config['SESSION_TYPE'] = 'filesystem'  # Store session data in files instead of cookies
app.config['SESSION_PERMANENT'] = False  # Prevent session expiry issues
app.config['SESSION_USE_SIGNER'] = True  # Protect session integrity
app.config['SESSION_FILE_DIR'] = os.path.join(os.getcwd(), 'flask_sessions')  # Store sessions in a dedicated folder

Session(app)  # Initialize session handling

# Ensure logging is set up BEFORE running the app
log_folder = app.config.get('LOG_FOLDER', 'logs')
os.makedirs(log_folder, exist_ok=True)
log_file_path = os.path.join(log_folder, 'debug.log')

# Remove existing handlers to prevent duplicate logs
logger = logging.getLogger()
if logger.hasHandlers():
    logger.handlers.clear()

# Configure logging with a file handler
file_handler = logging.FileHandler(log_file_path, mode='a')
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Also log to console (useful for debugging)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Set logging level globally
logger.setLevel(logging.INFO)

# Log initialization
logging.info(f"✅ Logging initialized at: {log_file_path}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)  # ✅ No SocketIO


'''from app import create_app, socketio
import os
config_name = os.getenv('FLASK_CONFIG') or 'development'

app = create_app(config_name)
if __name__ == '__main__':
    #socketio.run(app)
    socketio.run(app, debug=True, host='0.0.0.0', port=5001)
'''
'''from app import create_app
import os
import logging

# Select environment configuration
config_name = os.getenv('FLASK_CONFIG') or 'development'
app = create_app(config_name)

# Ensure logging is set up BEFORE running the app
log_folder = app.config.get('LOG_FOLDER', 'logs')
os.makedirs(log_folder, exist_ok=True)
log_file_path = os.path.join(log_folder, 'debug.log')

# Remove existing handlers if present
if logging.getLogger().hasHandlers():
    logging.getLogger().handlers.clear()

# Configure logging
file_handler = logging.FileHandler(log_file_path)
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
file_handler.setFormatter(formatter)
logging.getLogger().addHandler(file_handler)

logging.info("✅ Logging initialized before starting Flask app.")

if __name__ == '__main__':
    #app.run(host='0.0.0.0', port=5001, debug=True)  # ✅ Disable auto-reload
    app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)  '''# ✅ Disable auto-reload


