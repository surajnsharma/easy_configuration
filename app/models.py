#models.py

from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from influxdb import InfluxDBClient


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')
    telemetry_pid = db.Column(db.Integer, nullable=True)  # tracking start/stop telemetry

    # Relationships
    devices = db.relationship('DeviceInfo', backref='user', cascade='all, delete-orphan')
    trigger_events = db.relationship('TriggerEvent', backref='user_trigger_event', cascade='all, delete-orphan')
    topologies = db.relationship('Topology', backref='user_topology', cascade='all, delete-orphan')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class TriggerEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(150), nullable=False)
    iteration = db.Column(db.Integer, nullable=False)
    device_name = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    command = db.Column(db.Text, nullable=True)
    #user = db.relationship('User', backref=db.backref('trigger_events', lazy=True, cascade='all, delete-orphan'))


class DeviceInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    hostname = db.Column(db.String(150), nullable=False)
    ip = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # Ensure that each user has unique devices based on IP
    __table_args__ = (
        db.UniqueConstraint('user_id', 'ip', name='unique_user_device'),
    )


class GNMIPath(db.Model):
    __tablename__ = 'gnmi_paths'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)  # Assuming you want to associate paths with a specific user
    path = db.Column(db.String(255), nullable=False)

    def __init__(self, user_id, path):
        self.user_id = user_id
        self.path = path

class Topology(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    csv_data = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    #user = db.relationship('User', backref=db.backref('topologies', lazy=True, cascade='all, delete-orphan'))


"""class Topology(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    csv_data = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('topologies', lazy=True))"""

# Database model for storing onboarded GPU systems
"""class GpuSystem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    node_ip = db.Column(db.String(100), nullable=False)
    user = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    #color = db.Column(db.String(20), nullable=True)
    __table_args__ = (
        db.UniqueConstraint('node_ip', 'user', name='unique_node_user'),
    )"""

class GpuSystem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    node_ip = db.Column(db.String(100), nullable=False)
    user = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    color = db.Column(db.String(20), nullable=True)  # Add color field here
    __table_args__ = (
        db.UniqueConstraint('node_ip', 'user', name='unique_node_user'),
    )

class InfluxQuery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    measurement = db.Column(db.String(255), nullable=False)
    columns = db.Column(db.String(500), nullable=False)  # Increased length to prevent truncation
    interface_columns = db.Column(db.String(500), nullable=True)  # New field for interface query

    def __init__(self, user_id, measurement, columns, interface_columns=None):
        self.user_id = user_id
        self.measurement = measurement
        self.columns = columns
        self.interface_columns = interface_columns  # Optional for backward compatibility



