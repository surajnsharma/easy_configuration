#models.py

from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from . import db



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
    training_data = db.relationship('TrainingData', backref='user_training_data', cascade='all, delete-orphan')

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
    version = db.Column(db.String(50), nullable=True)
    serial_number = db.Column(db.String(100), nullable=True)
    model = db.Column(db.String(100), nullable=True)
    up_time = db.Column(db.String(100), nullable=True)
    last_reboot_reason = db.Column(db.String(255), nullable=True)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    reachability_status = db.Column(db.String(50), nullable=True, default="unknown")
    # Ensure that each user has unique devices based on IP
    __table_args__ = (
        db.UniqueConstraint('user_id', 'ip', name='unique_user_device'),
    )

    def update_reachability(self, status):
        """Update the reachability status and commit to the database."""
        self.reachability_status = status
        self.last_updated = datetime.utcnow()
        db.session.commit()


class Topology(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    csv_data = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    #user = db.relationship('User', backref=db.backref('topologies', lazy=True, cascade='all, delete-orphan'))



class TrainingData(db.Model):
    __tablename__ = 'training_data'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    category = db.Column(db.String(255), nullable=False)
    pattern = db.Column(db.String(255), nullable=False)
    suggestion = db.Column(db.Text, nullable=False)
    __table_args__ = (
        db.UniqueConstraint('user_id', 'pattern', name='unique_user_pattern'),
    )
    def __repr__(self):
        return f'<TrainingData id={self.id}, category={self.category}, pattern={self.pattern}>'

