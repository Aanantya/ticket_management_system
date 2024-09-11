from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TextAreaField, SubmitField, PasswordField, DateField, BooleanField, FileField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Regexp, Optional
from datetime import date
from app.enums import TicketStatusEnum, TicketPriorityEnum, RoleEnum

class UserLoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Email(message='Invalid email format')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required')
    ])
    submit = SubmitField('Login')

class UserRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Email(message='Invalid email format'),
        Length(min=5, max=30, message='Username must be between 5 and 30 characters')
    ])
    mobile = StringField('Mobile Number', validators=[
        DataRequired(message='Mobile number is required'),
        Regexp(r'^\d{10}$', message='Mobile number must be 10 digits')
    ])
    firstname = StringField('First Name', validators=[
        DataRequired(message='First name is required'),
        Length(min=5, max=15, message='First name must be between 5 and 15 characters')
    ])
    lastname = StringField('Last Name', validators=[
        Length(min=5, max=15, message='Last name must be between 5 and 15 characters')
    ])
    role = SelectField('Role', choices=[(role.name, role.value) for role in RoleEnum], coerce=str, validators=[DataRequired(message='Role is required')])
    profile_pic = FileField('Profile Picture')
    status = BooleanField('Active Status', default=True)
    submit = SubmitField('Register')

class CreateTicketForm(FlaskForm):
    user = SelectField('User', choices=[], coerce=int, validators=[DataRequired(message='User is required')])
    mobile = StringField('Mobile Number', validators=[
        DataRequired(message='Mobile number is required'),
        Length(min=10, max=10, message='Mobile number must be 10 digits')
    ])
    assets = TextAreaField('Assets', validators=[
        DataRequired(message='Assets field is required'),
        Length(max=100, message='Assets description cannot exceed 100 characters')
    ])
    priority = SelectField('Priority', choices=[(priority.name, priority.value) for priority in TicketPriorityEnum], validators=[DataRequired(message='Priority is required')])
    serial_no = StringField('Serial Number', validators=[
        DataRequired(message='Serial number is required'),
        Length(min=5, max=15, message='Serial number must be between 5 and 15 characters')
    ])
    model_no = StringField('Model Number', validators=[
        DataRequired(message='Model number is required'),
        Length(min=5, max=15, message='Model number must be between 5 and 15 characters')
    ])
    assigned_to = SelectField('Assign To', choices=[], coerce=int, validators=[DataRequired(message='Agent is required')])
    ticket_status = SelectField('Ticket Status', choices=[(status.name, status.value) for status in TicketStatusEnum], default=TicketStatusEnum.PENDING.name, validators=[DataRequired(message='Ticket status is required')])
    submit = SubmitField('Create Ticket')

class GenerateReportForm(FlaskForm):
    def validate_start_date(form, field):
        if field.data < date.today():
            raise ValidationError("Start date cannot be in the past.")
    
    def validate_end_date(form, field):
        if field.data < form.start_date.data:
            raise ValidationError("End date must be after the start date.")

    start_date = DateField("Start Date", format='%Y-%m-%d', validators=[Optional()])
    end_date = DateField("End Date", format='%Y-%m-%d', validators=[Optional()])
    ticket_status = SelectField('Ticket Status', choices=[(status.name, status.value) for status in TicketStatusEnum])
    priority = SelectField('Priority', choices=[(priority.name, priority.value) for priority in TicketPriorityEnum])
    submit = SubmitField("Generate Report")
