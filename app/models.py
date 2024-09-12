from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from enum import Enum
from app.enums import TicketStatusEnum, RoleEnum
from flask_login import UserMixin

from datetime import datetime

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    mobile = db.Column(db.String(15), unique=True, nullable=False)
    firstname = db.Column(db.String(50), nullable=False)
    lastname = db.Column(db.String(50), nullable=False)
    role = db.Column(db.Enum(RoleEnum), nullable=False)
    profile_pic = db.Column(db.String(100), default='./static/default.jpg')
    status = db.Column(db.Boolean, default=True)  # True for active, False for inactive
    password = db.Column(db.String(200), nullable=False)

    # Relationship with Ticket model
    #tickets = db.relationship('Ticket', back_populates='user')
    tickets = db.relationship('Ticket', back_populates='user', foreign_keys='Ticket.user_id')   # one-many relationship

    """
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)
    """
    
    def __repr__(self):
        return f'<User {self.username}>'

# Ticket Model
class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)   # user created the ticket
    mobile = db.Column(db.String(15), nullable=False)
    assets = db.Column(db.String(100), nullable=False)
    priority = db.Column(db.String(20), nullable=False)  # Low, Medium, High, Emergency
    serial_no = db.Column(db.String(15), nullable=False)
    model_no = db.Column(db.String(15), nullable=False)
    ticket_status = db.Column(db.Enum(TicketStatusEnum), default=TicketStatusEnum.PENDING)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))   # user assigned to the ticket (one-one relationship)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)  # Timestamp for when the issue is resolved
    dispatched_at = db.Column(db.DateTime)  # Timestamp for when the product is dispatched
    closed_at = db.Column(db.DateTime)  # Timestamp for when the ticket is closed

    user = db.relationship('User', back_populates='tickets', foreign_keys=[user_id])
    assigned_agent = db.relationship('User', foreign_keys=[assigned_to])

    def __repr__(self):
        return f'<Ticket {self.id}>'
