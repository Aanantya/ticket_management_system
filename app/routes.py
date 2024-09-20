import os
from werkzeug.utils import secure_filename
from datetime import date
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

# tms app blueprint
tms = Blueprint('tms', __name__)

# Undefined error handling
@tms.errorhandler(UndefinedError)
def handle_undefined_error(error):
    # return redirect(request.referrer or url_for('tms.landing_page'))  # Fallback
    return '<h5>Undefined error occured</h5>'

@tms.errorhandler(403)
def forbidden_error(error):
    # return redirect(request.referrer or url_for('tms.landing_page'))  # Fallback
    return '<h5>Forbidden access</h5>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def role_required(role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('tms.login'))
            if current_user.role.name != role:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('unauthorized'))
            return func(*args, **kwargs)
        return wrapper
    return decorator

@login_required
@tms.route('/access-denied')
def access_denied():
    return '<h5>Access Denied</h5>'

@tms.route('/')
def landing_page():
    today = date.today()

    active_tickets_count = Ticket.query.filter(db.func.date(Ticket.created_at) == today).count()    # tickets had been generated today
    resolved_tickets_count = Ticket.query.filter(db.func.date(Ticket.resolved_at) == today, Ticket.ticket_status == 'RESOLVED').count()  # tickets had been resolved today
    closed_tickets_count = Ticket.query.filter_by(closed_at=today).count()  # tickets had been closed today
    active_agents_count = User.query.filter_by(role='AGENT', status=True).count()    # agents working on the tickets today

    return render_template('landing.html',
                           active_tickets_count=active_tickets_count,
                           resolved_tickets_count=resolved_tickets_count,
                           closed_tickets_count=closed_tickets_count,
                           active_agents_count=active_agents_count)

@tms.route('/login', methods=['GET', 'POST'])
def login():
    form = UserLoginForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data

            # Retrieve user
            user = User.query.filter_by(username=form.username.data).first()

            if user and bcrypt.check_password_hash(user.password, password):
                login_user(user)

                # Redirect based on role
                if user.role.name == 'ADMIN':
                    return redirect(url_for('admin_view'))
                elif user.role.name == 'SUBADMIN':
                    return redirect(url_for('subadmin_view'))
                elif user.role.name == 'AGENT':
                    return redirect(url_for('agent_view'))

            else:
                flash('Login unsuccessful. Please check username and password.') 

    return render_template('login.html', form=form)

@login_required
@tms.route('/logout', methods=['GET'])
def logout():
    session.clear()   
    logout_user()
    return redirect(url_for('landing_page'))

@login_required
@tms.route('/register', methods=['GET', 'POST'])
def register():
    form = UserRegistrationForm()
    
    # Only allow Admin to create Subadmins or Agents, and Subadmin to create Users
    if current_user.role.name == 'ADMIN':
        allowed_roles = ['SUBADMIN', 'AGENT']
    elif current_user.role.name == 'SUBADMIN':
        allowed_roles = ['USER']
    else:
        flash('You do not have permission to register new users.', 'danger')

    if request.method == 'POST':
        if form.validate_on_submit():

            # Check if the username already exists
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user:
                flash("Username already exists.", "danger")
                return render_template('register.html', form=form)

            # Ensure role selected is within allowed roles
            if form.role.data not in allowed_roles:
                flash(f"You can only create users with roles: {', '.join(allowed_roles)}", "danger")
                print(f"You can only create users with roles: {', '.join(allowed_roles)}", "danger")
                return render_template('register.html', form=form)

            # TBD: Upload the profile picture
            if form.profile_pic.data:
                profile_pic = form.profile_pic.data
                
                extension = os.path.splitext(profile_pic.filename)[1]   # extract file extension
                new_filename = f"{current_user.id}{extension}"    # new filename
                secure_filename(new_filename)
                file_path = os.path.join(app.config['PROFILE_PIC_STORAGE_FOLDER'], new_filename)
                profile_pic.save(file_path)

                print('file_path : ', file_path)
          
            # Autogeneration password
            if form.role.data == 'User':
                password = 'User@1234'
            else:
                password = f'{form.firstname.data.capitalize()}@1234'

            # Hashing password using pip install flask-bcrypt
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

            # Add user to the database
            db.session.add(new_user)
            db.session.commit()

            # Send mail on successful registration
            msg = Message(
                subject="Account Created Successfully",
                body=f"Dear User,\n\nThank you for registering! Your username: {new_user['username']} and password: {password}.",
                recipients=[new_user['username']]
            )

            try:
                mail.send(msg)
                print('Email sent successfully')
            except Exception as e:
                print(f"Failed to send email: {e}")

            flash('Registration successful.')

    return render_template('register.html', form=form)

@tms.route('/create-ticket', methods=['GET', 'POST'])
@role_required('SUBADMIN')
@login_required
def create_ticket():
    form = CreateTicketForm()
    print("role = ", current_user.role.name)

    # Populate user choices based on available users
    form.user.choices = [(user.id, user.username) for user in User.query.filter_by(role='USER').all()]
        
    # Populate agent choices based on available agents
    form.assigned_to.choices = [(assigned_to.id, assigned_to.username) for assigned_to in User.query.filter_by(role='AGENT').all()]

    if request.method == 'POST' and form.validate_on_submit():
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
            db.session.add(new_ticket)
            db.session.commit()

            flash('Ticket created successfully!', 'success')
            
            return redirect(request.referrer or url_for('tms.subadmin_view'))

        except Exception as e:
            # Rollback changes
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')

    return render_template('create_ticket.html', form=form)


@tms.route('/generate-report', methods=['GET', 'POST'])
@role_required('SUBADMIN')
@login_required
def generate_report():
    form = GenerateReportForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        # Collect form data
        start_date = form.start_date.data
        end_date = form.end_date.data
        ticket_status = form.ticket_status.data
        priority = form.priority.data

        print(start_date, end_date, ticket_status, priority)
        
        # Base query
        query = Ticket.query
        
        # Apply filters conditionally
        if start_date:
            query = query.filter(Ticket.created_at >= start_date)
        if end_date:
            query = query.filter(Ticket.created_at <= end_date)
        if ticket_status != 'NONE':
            query = query.filter(Ticket.ticket_status == ticket_status)
        if priority != 'NONE':
            query = query.filter(Ticket.priority == priority)

        # Retrieve all the results
        tickets = query.all()

        print(tickets)
        return render_template('generate_report.html', form=form, tickets=tickets)

    return render_template('generate_report.html', form=form, tickets=None)


@login_required
@role_required('AGENT')
@tms.route('/update-ticket-status/<int:ticket_id>', methods=['POST'])
def update_ticket_status(ticket_id):

    # Retrieve ticket data by ticket_id
    ticket = Ticket.query.filter_by(id=ticket_id).first()

    # Collect new ticket status
    new_ticket_status = request.form.get('ticket_status')

    # Update the status if ticket exists
    if ticket:
        Ticket.query.filter_by(id=ticket_id).update({"ticket_status": new_ticket_status})
        db.session.commit()

    return redirect(request.referrer or url_for('tms.agent_view'))

# TBD send_email on successful user registration
def send_email():
    return 

# TBD Copy the profile_pic to local dir
def fileupload():
    return

@login_required
@role_required('ADMIN')
@tms.route('/admin')
def admin_view():
    user = current_user # logged in user
    return render_template('admin_view.html', user=user)

@tms.route('/sub-admin')
@role_required('SUBADMIN')
@login_required
def subadmin_view():
    user = current_user # logged in user
    return render_template('subadmin_view.html', user=user)

@tms.route('/agent')
@role_required('AGENT')
@login_required
def agent_view():
    user = current_user # logged in user

    # Populate all the tickets assigned to the user (Agent)
    tickets = Ticket.query.filter_by(assigned_to=current_user.id).all()
    print('tickets = ', tickets)
    return render_template('agent_view.html', tickets=tickets, ticket_status_enum=TicketStatusEnum)
