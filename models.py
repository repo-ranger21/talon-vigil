"""
Database models for TalonVigil
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from typing import Optional

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    
    # Relationships
    roles = db.relationship('UserRole', back_populates='user', cascade='all, delete-orphan')

    def set_password(self, password: str):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Check password"""
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self) -> bool:
        """Check if user is admin"""
        return any(role.role.name == 'admin' for role in self.roles)
    
    def has_role(self, role_name: str) -> bool:
        """Check if user has specific role"""
        return any(role.role.name == role_name for role in self.roles)
    
    def get_roles(self) -> list:
        """Get user roles"""
        return [role.role.name for role in self.roles]

    def __repr__(self):
        return f"<User {self.email}>"

class Role(db.Model):
    __tablename__ = "roles"
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))
    
    # Relationships
    users = db.relationship('UserRole', back_populates='role')

class UserRole(db.Model):
    __tablename__ = "user_roles"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    
    # Relationships
    user = db.relationship('User', back_populates='roles')
    role = db.relationship('Role', back_populates='users')

class ThreatEvent(db.Model):
    __tablename__ = "threat_events"
    
    id = db.Column(db.String(50), primary_key=True)
    event_type = db.Column(db.String(50), nullable=False)
    source_ip = db.Column(db.String(45))
    destination_ip = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    raw_score = db.Column(db.Float, default=0.0)
    adjusted_score = db.Column(db.Float, default=0.0)
    risk_level = db.Column(db.String(20))
    confidence = db.Column(db.Float, default=0.0)
    metadata = db.Column(db.JSON)
    analyst_feedback = db.Column(db.String(500))
    
    def to_dict(self):
        return {
            'id': self.id,
            'event_type': self.event_type,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'raw_score': self.raw_score,
            'adjusted_score': self.adjusted_score,
            'risk_level': self.risk_level,
            'confidence': self.confidence,
            'metadata': self.metadata,
            'analyst_feedback': self.analyst_feedback
        }

class SOARIncident(db.Model):
    __tablename__ = "soar_incidents"
    
    id = db.Column(db.String(50), primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='open')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    platform_ids = db.Column(db.JSON)  # Store platform-specific IDs
    tags = db.Column(db.JSON)
    
    # Relationships
    assignee = db.relationship('User')

def init_db():
    """Initialize database with default data"""
    db.create_all()
    
    # Create default roles
    if not Role.query.filter_by(name='admin').first():
        roles = [
            Role(name='admin', description='Administrator'),
            Role(name='analyst', description='Security Analyst'),
            Role(name='operator', description='SOC Operator'),
            Role(name='compliance_officer', description='Compliance Officer'),
            Role(name='viewer', description='Read-only Viewer')
        ]
        for role in roles:
            db.session.add(role)
    
    # Create default admin user if none exists
    if not User.query.filter_by(email='admin@talonvigil.com').first():
        admin_user = User(
            email='admin@talonvigil.com',
            username='admin',
            name='System Administrator'
        )
        admin_user.set_password('TalonVigil2025!')
        db.session.add(admin_user)
        db.session.flush()  # Get user ID
        
        # Assign admin role
        admin_role = Role.query.filter_by(name='admin').first()
        if admin_role:
            user_role = UserRole(user_id=admin_user.id, role_id=admin_role.id)
            db.session.add(user_role)
    
    db.session.commit()