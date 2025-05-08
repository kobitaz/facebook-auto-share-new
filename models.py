"""
Models for the Facebook Auto Share application
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """User model for authentication"""
    __tablename__ = 'users'  # Define explicit table name
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_premium = db.Column(db.Boolean, default=False)
    last_login_ip = db.Column(db.String(50), nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_blocked = db.Column(db.Boolean, default=False)
    login_count = db.Column(db.Integer, default=0)
    session_token = db.Column(db.String(256), nullable=True)  # For persistent login
    
    # Define relationships
    access_logs = db.relationship('UserAccessLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    share_history = db.relationship('ShareHistory', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    @property
    def password(self):
        """Password is not readable"""
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        """Verify password"""
        return check_password_hash(self.password_hash, password)
        
    @classmethod
    def create_admin(cls):
        """Create admin user if it doesn't exist"""
        admin = cls.query.filter_by(username='jade').first()
        if not admin:
            admin = cls()
            admin.username = 'jade'
            admin.is_admin = True
            admin.password = 'jade1433'  # This will be hashed
            db.session.add(admin)
            db.session.commit()
            return True
        return False
        
class UserAccessLog(db.Model):
    """Log of user access to the application"""
    __tablename__ = 'user_access_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    user_agent = db.Column(db.String(512), nullable=True)
    accessed_at = db.Column(db.DateTime, default=datetime.utcnow)
    action = db.Column(db.String(255), nullable=True)  # e.g. 'login', 'auto_share', 'cookie_getter'
    
    def __init__(self, user_id=None, ip_address=None, user_agent=None, action=None):
        """Initialize UserAccessLog with optional parameters"""
        self.user_id = user_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.action = action

class ShareHistory(db.Model):
    """History of share tasks performed by the user"""
    __tablename__ = 'share_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    task_id = db.Column(db.String(100), unique=True, nullable=False)
    post_url = db.Column(db.String(512), nullable=False)
    share_count = db.Column(db.Integer, nullable=False)
    delay = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    current_count = db.Column(db.Integer, default=0)
    success_count = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='running')  # running, completed, failed, paused
    messages = db.Column(db.Text, nullable=True)  # JSON serialized messages
    
    def to_dict(self):
        """Convert object to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'task_id': self.task_id,
            'post_url': self.post_url,
            'share_count': self.share_count,
            'delay': self.delay,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'completed_at': self.completed_at.strftime('%Y-%m-%d %H:%M:%S') if self.completed_at else None,
            'current_count': self.current_count,
            'success_count': self.success_count,
            'status': self.status,
            'progress_percentage': int((self.current_count / self.share_count * 100) if self.share_count > 0 else 0),
            'messages': json.loads(self.messages) if self.messages else []
        }
