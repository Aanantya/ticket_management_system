# queries.py

from app import db
from app.models import User, Ticket
from app.enums import TicketStatusEnum
from datetime import date
from sqlalchemy import and_

# Function to get today's date
def get_today():
    return date.today()

# User-related queries
# Get user by user_id
def get_user_by_id(user_id):
    return User.query.get(int(user_id))

# Get user by username
def get_user_by_username(username):
    return User.query.filter_by(username=username).first()

# Add new user
def add_user(new_user):
    db.session.add(new_user)
    db.session.commit()

# Get count of active agents
def get_active_agents_count():
    return User.query.filter(
        and_(
            User.role == 'AGENT',
            User.status == True
        )
    ).count()

# Get all existing users
def get_user_choices(role):
    return [(user.id, user.username) for user in User.query.filter_by(role=role).all()]

# Ticket-related queries
# Add new ticket
def create_ticket(ticket_data):
    db.session.add(ticket_data)
    db.session.commit()

# Get ticket by ticket id
def get_ticket_by_id(ticket_id):
    return Ticket.query.filter_by(id=ticket_id).first()

# Update ticket status
def update_ticket_status(ticket_id, new_status):
    Ticket.query.filter_by(id=ticket_id).update({"ticket_status": new_status})
    db.session.commit()

# Get tickets count by date
def get_tickets_by_date(date_filter, status=None):
    query = Ticket.query.filter(db.func.date(Ticket.created_at) == date_filter)
    if status:
        query = query.filter(Ticket.ticket_status == status)
    return query.count()

# Get tickets assigned to the user id
def get_tickets_by_user(user_id):
    return Ticket.query.filter_by(assigned_to=user_id).all()

# Filter tickets
def filter_tickets_by_criteria(start_date, end_date, ticket_status, priority):
    query = Ticket.query
    if start_date:
        query = query.filter(Ticket.created_at >= start_date)
    if end_date:
        query = query.filter(Ticket.created_at <= end_date)
    if ticket_status != 'NONE':
        query = query.filter(Ticket.ticket_status == ticket_status)
    if priority != 'NONE':
        query = query.filter(Ticket.priority == priority)
    
    return query.all()

# Get count of tickets created today
def get_active_tickets_count():
    today = get_today()
    return Ticket.query.filter(db.func.date(Ticket.created_at) == today).count()

# Get count of tickets resolved today
def get_resolved_tickets_count():
    today = get_today()
    return Ticket.query.filter(
        and_(
            db.func.date(Ticket.updated_at) == today,
            Ticket.ticket_status == 'resolved'
        )
    ).count()

# Get count of tickets closed today
def get_closed_tickets_count():
    today = get_today()
    return Ticket.query.filter(
        and_(
            db.func.date(Ticket.updated_at) == today,
            Ticket.ticket_status == 'closed'
        )
    ).count()

# Rollback session
def session_rollback():
    db.session.rollback()