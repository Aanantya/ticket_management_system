from app import app, bcrypt, db
from datetime import date
from flask import render_template, redirect, url_for, request, flash

from app.models import User, Ticket

from app.forms import UserLoginForm, UserRegistrationForm, CreateTicketForm, GenerateReportForm

from flask_login import LoginManager, login_user, login_required, logout_user, current_user

login_manager = LoginManager(app)
# login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def landing_page():
    today = date.today()
    """
    # Fetching ticket and agent counts (dummy values for now)
    active_tickets_count = Ticket.query.filter_by(date_created=today, status='Active').count()
    resolved_tickets_count = Ticket.query.filter_by(date_resolved=today).count()
    closed_tickets_count = Ticket.query.filter_by(date_closed=today).count()
    active_agents_count = User.query.filter_by(role='Agent', is_active=True).count()

    return render_template('landing.html',
                           active_tickets_count=active_tickets_count,
                           resolved_tickets_count=resolved_tickets_count,
                           closed_tickets_count=closed_tickets_count,
                           active_agents_count=active_agents_count)
    """
    return render_template('landing.html')


@app.route('/login', methods=['GET', 'POST'])
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

                return redirect(url_for('admin_view'))

            else:
                flash('Login unsuccessful. Please check username and password.') 

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    return redirect(url_for('landing_page'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = UserRegistrationForm()

    if request.method == 'POST':
        if form.validate_on_submit():

            # Check if the username already exists
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user:
                flash("Username already exists.", "danger")
                return render_template('register.html', form=form)

            # TBD: Upload the profile picture
            if form.profile_pic.data:
                pic = form.profile_pic.data

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
                status=form.status.data
            )

            print('new_user: ', new_user)

            # TBD Add user to the database
            db.session.add(new_user)
            db.session.commit()

            # TBD Send mail on successful registration

            flash('Registration successful.')
            return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/create-ticket')
def create_ticket():
    form = CreateTicketForm()
    return render_template('create_ticket.html', form=form)

@app.route('/generate-report')
def generate_report():
    form = GenerateReportForm()
    if form.validate_on_submit():
        # Collect form data
        startdate = form.startdate.data
        enddate = form.enddate.data
        ticketstatus = form.ticketstatus.data
        priority = form.priority.data

        # Placeholder for actual report generation logic
        # Replace this with actual querying logic from the database
        report_data = {
            'startdate': startdate,
            'enddate': enddate,
            'ticketstatus': ticketstatus,
            'priority': priority
        }

        # Render the report result in the same template
        return render_template('generate_report.html', form=form, report=report_data)

    # On GET request, render the form
    return render_template('generate_report.html', form=form)


@app.route('/view-tickets-assigned')
def view_tickets_assigned():
    return 

@app.route('/update-ticket-status')
def update_ticket_status():
    return

# send_email on successful user registration
def send_email():
    return 

@app.route('/admin')
def admin_view():
    user = current_user
    return render_template('admin_view.html', user=user)

@app.route('/sub-admin')
def subadmin_view():
    user = current_user
    return render_template('subadmin_view.html', user=user)

@app.route('/agent')
def agent_view():
    tickets = [{'id': 1, 'title': 'Issue with login', 'description': 'Unable to login', 'status': 'Open'}]
    return render_template('agent_view.html', tickets=[])
