#__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from app.config import config
from flask_socketio import SocketIO
import os
from flask_login import LoginManager

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
socketio = SocketIO()
migrate = Migrate()

def create_app(config_name):
    app = Flask(__name__, template_folder='templates')
    # Load the correct config class
    app.config.from_object(config[config_name])
    # Ensure you have a secret key for session management
    app.secret_key = app.config['SECRET_KEY']
    # Initialize extensions with the app
    db.init_app(app)
    socketio.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    # Ensure necessary folders exist
    with app.app_context():
        # Directly call the ensure_folders() method from the loaded config class
        config_class = config[config_name]()
        config_class.ensure_folders()
        # Import and register routes
        from . import routes
        routes.create_routes(app)
        # Avoid using db.create_all(); use flask-migrate for production-ready setups.
        # db.create_all()
    return app


'''from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from app.config import config
from flask_socketio import SocketIO
import os
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
socketio = SocketIO()
migrate = Migrate()

def create_app(config_name):
    app = Flask(__name__, template_folder='templates')
    app.config.from_object(config[config_name])  # Load the correct config class
    app.secret_key = app.config['SECRET_KEY']  # Ensure you have a secret key for session management
    # Initialize extensions with the app
    db.init_app(app)
    socketio.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    # Ensure necessary folders exist
    with app.app_context():
        # Import and register routes
        from . import routes
        routes.create_routes(app)
        db.create_all()  # Create database tables for our data models

    return app'''

