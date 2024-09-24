'''TMS app models'''
from app import db
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
    profile_pic = db.Column(db.String(100))
    status = db.Column(db.Boolean, default=True)  # True for active, False for inactive
    password = db.Column(db.String(200), nullable=False)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)  # Timestamp for when the user is created
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)  # Timestamp for updates

    # Relationship with Ticket model
    tickets = db.relationship('Ticket', back_populates='user', foreign_keys='Ticket.user_id')

    def __repr__(self):
        return f'<User {self.username}>'

# Ticket Model
class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)   # User created the ticket
    mobile = db.Column(db.String(15), nullable=False)
    assets = db.Column(db.String(100), nullable=False)
    priority = db.Column(db.String(20), nullable=False)
    serial_no = db.Column(db.String(15), nullable=False)
    model_no = db.Column(db.String(15), nullable=False)
    ticket_status = db.Column(db.Enum(TicketStatusEnum), default=TicketStatusEnum.PENDING)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))   # user assigned to the ticket

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)  # Timestamp for when the ticket is created
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)  # Timestamp for updates
    approved_at = db.Column(db.DateTime)  # Timestamp for when the ticket is approved
    ready_to_dispatch_at = db.Column(db.DateTime)  # Timestamp for when the ticket ready to dispatch
    dispatched_at = db.Column(db.DateTime)  # Timestamp for when the ticket is dispatched

    user = db.relationship('User', back_populates='tickets', foreign_keys=[user_id])
    assigned_agent = db.relationship('User', foreign_keys=[assigned_to])

    def __repr__(self):
        return f'<Ticket {self.id}>'
