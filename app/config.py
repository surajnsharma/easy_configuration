#config.py
import os
import logging

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'supersecretkey'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app_database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    LOG_FOLDER = os.path.join(BASE_DIR, 'logs')
    TELEMETRY_FOLDER = os.path.join(BASE_DIR, 'telemetry')
    DEVICE_CONFIG_FOLDER = os.path.join(BASE_DIR, 'device_config')
    #LOG_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'logs')
    def ensure_folders(self):
        folders = [self.UPLOAD_FOLDER, self.LOG_FOLDER, self.TELEMETRY_FOLDER]
        for folder in folders:
            if not os.path.exists(folder):
                os.makedirs(folder)
    def create_user_folders(self, username):
        """
        Create user-specific folders for uploads, logs, and telemetry data.
        """
        user_folder = os.path.join(self.BASE_DIR, 'uploads', username)
        log_folder = os.path.join(self.BASE_DIR, 'logs', username)
        telemetry_folder = os.path.join(self.BASE_DIR, 'telemetry', username)
        device_config_folder=os.path.join(self.BASE_DIR, 'device_config', username)
        # Ensure the folders are created
        os.makedirs(user_folder, exist_ok=True)
        os.makedirs(log_folder, exist_ok=True)
        os.makedirs(telemetry_folder, exist_ok=True)
        os.makedirs(device_config_folder, exist_ok=True)
        return user_folder, log_folder, telemetry_folder,device_config_folder

    def setup_logging(self, log_folder=None):
        """
        Sets up logging to the specified log folder or default log folder if user is not logged in.
        """
        if log_folder is None:
            log_folder = self.LOG_FOLDER  # Default to the base log folder if no user is logged in
        # Ensure the log folder exists
        if not os.path.exists(log_folder):
            os.makedirs(log_folder, exist_ok=True)
        # Define the log file path
        log_file_path = os.path.join(log_folder, 'debug.log')
        print(f"Log file path: {log_file_path}")
        # Get the root logger and clear any existing handlers
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)  # Set level to INFO for logging
        # Remove all existing handlers if present to prevent duplicates
        if root_logger.hasHandlers():
            root_logger.handlers.clear()
        # Create a new file handler
        file_handler = logging.FileHandler(log_file_path)
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
        file_handler.setFormatter(formatter)

        # Add the file handler to the root logger
        root_logger.addHandler(file_handler)

        # Log the initialization message
        root_logger.info(f"Logging initialized at {log_file_path}")


config = Config()
#config.ensure_folders()

config.ensure_folders()


class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig
}



'''#config.py
import os
import logging

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'supersecretkey'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app_database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    LOG_FOLDER = os.path.join(BASE_DIR, 'logs')
    TELEMETRY_FOLDER = os.path.join(BASE_DIR, 'telemetry')
    DEVICE_CONFIG_FOLDER = os.path.join(BASE_DIR, 'device_config')
    #LOG_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'logs')
    def ensure_folders(self):
        folders = [self.UPLOAD_FOLDER, self.LOG_FOLDER, self.TELEMETRY_FOLDER]
        for folder in folders:
            if not os.path.exists(folder):
                os.makedirs(folder)
    def create_user_folders(self, username):
        """
        Create user-specific folders for uploads, logs, and telemetry data.
        """
        user_folder = os.path.join(self.BASE_DIR, 'uploads', username)
        log_folder = os.path.join(self.BASE_DIR, 'logs', username)
        telemetry_folder = os.path.join(self.BASE_DIR, 'telemetry', username)
        device_config_folder=os.path.join(self.BASE_DIR, 'device_config', username)
        # Ensure the folders are created
        os.makedirs(user_folder, exist_ok=True)
        os.makedirs(log_folder, exist_ok=True)
        os.makedirs(telemetry_folder, exist_ok=True)
        os.makedirs(device_config_folder, exist_ok=True)
        return user_folder, log_folder, telemetry_folder,device_config_folder

    def setup_logging(self, log_folder=None):
        """
        Sets up logging to the specified log folder or default log folder if user is not logged in.
        """
        if log_folder is None:
            log_folder = self.LOG_FOLDER  # Default to the base log folder if no user is logged in
        # Ensure the log folder exists
        if not os.path.exists(log_folder):
            os.makedirs(log_folder, exist_ok=True)
        # Define the log file path
        log_file_path = os.path.join(log_folder, 'debug.log')
        logging.info(log_file_path)
        # Set up the logging configuration
        logging.basicConfig(
            filename=log_file_path,
            level=logging.INFO,  # Set to INFO level for logging
            format='%(asctime)s [%(levelname)s] %(message)s',
            filemode='w'  # 'w' ensures that the log file is overwritten each time
        )
        print(f"log_file_path: {log_file_path}")
        logging.info(f"Logging initialized at {log_file_path}")



config = Config()
#config.ensure_folders()

config.ensure_folders()


class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig
}
'''