import os
from werkzeug.utils import secure_filename
from datetime import date, datetime
from functools import wraps
from flask import render_template, redirect, url_for, request, flash, session
from flask import Blueprint
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_mail import Message
from jinja2.exceptions import UndefinedError

from app import bcrypt, db, mail, login_manager
from app.models import User, Ticket
from app.enums import TicketStatusEnum
from app.forms import UserLoginForm, UserRegistrationForm, CreateTicketForm, GenerateReportForm
from app.file_upload import save_profile_picture
from app.ticket_overview import get_data_from_cache_or_source
from app.queries import (
    get_user_by_id, get_user_by_username, add_user, get_ticket_by_id,
    add_ticket, update_ticket_status, get_tickets_by_user, filter_tickets_by_criteria,
    get_active_tickets_count, get_resolved_tickets_count, get_closed_tickets_count,
    get_active_agents_count, session_rollback, get_user_choices
)

# tms app blueprint
tms = Blueprint('tms', __name__)

# Undefined error handling
@tms.errorhandler(UndefinedError)
def handle_undefined_error(error):
    return render_template('error.html', message="Undefined error occurred"), 500

@tms.errorhandler(403)
def forbidden_error(error):
    return render_template('error.html', message="Forbidden access"), 403

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)

def role_required(*roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('tms.login'))
            print(f"Checking roles: {roles} for user: {current_user.role.name}")
            
            if current_user.role.name not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('tms.access_denied'))
            return func(*args, **kwargs)
        return wrapper
    return decorator

@login_required
@tms.route('/access-denied')
def access_denied():
    return render_template('access_denied.html', message="Access Denied")

@tms.route('/')
def landing_page():
    try:
        today = date.today()
        # Get data from database
        active_tickets_count = get_data_from_cache_or_source('active_tickets_count', get_active_tickets_count)
        resolved_tickets_count = get_data_from_cache_or_source('resolved_tickets_count', get_resolved_tickets_count)
        closed_tickets_count = get_data_from_cache_or_source('closed_tickets_count', get_closed_tickets_count)
        active_agents_count = get_data_from_cache_or_source('active_agents_count', get_active_agents_count)
        return render_template('landing.html',
                            active_tickets_count=active_tickets_count,
                            resolved_tickets_count=resolved_tickets_count,
                            closed_tickets_count=closed_tickets_count,
                            active_agents_count=active_agents_count)
    except Exception as e:
        flash('Error loading the actual count', 'info')
        return render_template('landing.html',
                            active_tickets_count=16,
                            resolved_tickets_count=20,
                            closed_tickets_count=15,
                            active_agents_count=25)

@tms.route('/login', methods=['GET', 'POST'])
def login():
    form = UserLoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Retrieve user
        user = get_user_by_username(username=form.username.data)
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful.', 'success')

            # Redirect based on role
            if user.role.name == 'ADMIN':
                return redirect(url_for('tms.admin_view'))
            elif user.role.name == 'SUBADMIN':
                return redirect(url_for('tms.subadmin_view'))
            elif user.role.name == 'AGENT':
                return redirect(url_for('tms.agent_view'))

        else:
            flash('Login unsuccessful. Please check username and password.', 'warning') 
    return render_template('login.html', form=form)

@login_required
@tms.route('/logout', methods=['GET'])
def logout():
    try:
        logout_user()
        return redirect(url_for('tms.landing_page'))
    except Exception as e:
        flash('Error while logout.', 'warning')

@tms.route('/register', methods=['GET', 'POST'])
@login_required
@role_required('ADMIN', 'SUBADMIN')
def register():
    try:
        form = UserRegistrationForm()
        
        if current_user.role.name == 'ADMIN':
            allowed_roles = ['SUBADMIN', 'AGENT']   # Admin can create Subadmins or Agents
        elif current_user.role.name == 'SUBADMIN':
            allowed_roles = ['USER']    # Subadmin can create Users
        else:
            flash('You do not have permission to register new users.', 'danger')

        if form.validate_on_submit():
            # Check if the username already exists
            existing_user = get_user_by_username(username=form.username.data)
            
            if existing_user:
                flash("Username already exists.", "danger")
                # return redirect(request.referrer)

            # Ensure role selected is within allowed roles
            if form.role.data not in allowed_roles:
                flash(f"You can only create users with roles: {', '.join(allowed_roles)}", "danger")
                #print(f"You can only create users with roles: {', '.join(allowed_roles)}", "danger")
                #return redirect(request.referrer)

            # TBD: Upload the profile picture
            if form.profile_pic.data:
                profile_pic = form.profile_pic.data
                
                current_timestamp = datetime.now().timestamp()
                standard_filename = int(current_timestamp)  # current timestamp as standard filename
                file_path = save_profile_picture(profile_pic, standard_filename)
                print('file_path : ', file_path)            
            else:
                file_path = './static/default.jpg'

            # Autogeneration password
            if form.role.data == 'User':
                password = 'User@1234'
            else:
                password = f'{form.firstname.data.capitalize()}@1234'

            # Hashing password using bcrypt
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Create new user
            new_user = User(
                username=form.username.data,
                mobile=form.mobile.data,
                firstname=form.firstname.data,
                lastname=form.lastname.data,
                password=hashed_password,
                role=form.role.data,
                profile_pic=file_path,
                status=form.status.data
            )

            print('new_user: ', new_user)

            # Email draft
            msg = Message(
                subject="Account Created Successfully",
                body=f"Dear User,\n\nThank you for registering! Your username: {form.username.data} and password: {password}.",
                recipients=[form.username.data]
            )         
            try:
                add_user(new_user)  # Add user to the database
                #mail.send(msg)  # Send email
                flash('User created successfully.', 'success')
                print('User created successfully.', 'success')
            except Exception as e:
                session_rollback()   # Rollback changes
                flash('Failed to create new user.', 'danger')
                print(f"Failed to send email: {e}. Rolling back changes ...")
            finally:
                return redirect(request.referrer)
        
        return render_template('register.html', form=form)

    except Exception as e:
        print(f'Error occured, {e}')
        return f'Exception: {e}'

@tms.route('/create-ticket', methods=['GET', 'POST'])
@role_required('SUBADMIN')
@login_required
def create_ticket():
    try:
        form = CreateTicketForm()
        # Populate user choices based on available users
        form.user.choices = get_user_choices(role='USER')
        # Populate agent choices based on available agents
        form.assigned_to.choices = get_user_choices(role='AGENT')

        if form.validate_on_submit():
            try:
                # Create a new ticket
                new_ticket = Ticket(
                    user_id=form.user.data,
                    mobile=form.mobile.data,
                    assets=form.assets.data,
                    priority=form.priority.data,
                    serial_no=form.serial_no.data,
                    model_no=form.model_no.data,
                    ticket_status=form.ticket_status.data,
                    assigned_to=form.assigned_to.data,
                )

                # Save the ticket to the database
                add_ticket(new_ticket)
                flash('Ticket created successfully!', 'success')
                return redirect(request.referrer or url_for('tms.subadmin_view'))

            except Exception as e:
                # Rollback changes
                session_rollback()
                flash(f'An error occurred: {str(e)}', 'danger')

        return render_template('create_ticket.html', form=form)

    except Exception as e:
        return f'Error occured, {e}'

@tms.route('/generate-report', methods=['GET', 'POST'])
@role_required('SUBADMIN')
@login_required
def generate_report():
    try:
        form = GenerateReportForm()
        
        if form.validate_on_submit():
            # Collect form data
            start_date = form.start_date.data
            end_date = form.end_date.data
            ticket_status = form.ticket_status.data
            priority = form.priority.data

            print(start_date, end_date, ticket_status, priority)

            tickets = filter_tickets_by_criteria(start_date, end_date, ticket_status, priority)
            print(tickets)
            
            return render_template('generate_report.html', form=form, tickets=tickets)

        return render_template('generate_report.html', form=form, tickets=None)
    except Exception as e:
        print(f'Error occured, {e}')

@login_required
@role_required('AGENT')
@tms.route('/update-ticket-status/<int:ticket_id>', methods=['POST'])
def ticket_status_update(ticket_id):
    try:
        # Retrieve ticket data by ticket_id
        ticket = get_ticket_by_id(ticket_id)

        # Collect new ticket status
        #if form.validate_on_submit():
        new_ticket_status = request.form.get('ticket_status')
        # Update the status if ticket exists
        if ticket:
            print('new_ticket_status: ', new_ticket_status)
            update_ticket_status(ticket_id=ticket_id, new_status=new_ticket_status)
        
        return redirect(request.referrer or url_for('tms.agent_view'))
    except Exception as e:
        return f'Error occured, {e}'

@login_required
@role_required('ADMIN')
@tms.route('/admin')
def admin_view():
    try:
        user = current_user # logged in user
        return render_template('admin_view.html', user=user)
    except Exception as e:
        return f'Error occured, {e}'

@tms.route('/sub-admin')
@role_required('SUBADMIN')
@login_required
def subadmin_view():
    try:
        user = current_user # logged in user
        return render_template('subadmin_view.html', user=user)
    except Exception as e:
        return f'Error occured, {e}'

@tms.route('/agent')
@role_required('AGENT')
@login_required
def agent_view():
    try:
        user = current_user # logged in user
        # Populate all the tickets assigned to the user (Agent)
        tickets = Ticket.query.filter_by(assigned_to=current_user.id).all()
        print('tickets = ', tickets)
        return render_template('agent_view.html', tickets=tickets, ticket_status_enum=TicketStatusEnum)
    except Exception as e:
        return f'Error occured, {e}'