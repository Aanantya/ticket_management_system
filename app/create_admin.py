from app import db, bcrypt
from app.models import User

def create_default_user():
    # Check if the admin user already exists
    existing_user = User.query.filter_by(username='admin@gmail.com').first()
    
    if not existing_user:
        # Create a new admin user if one does not exist
        default_user = User(
            username='admin@gmail.com',
            mobile='1234567890',  # Change as needed
            firstname='Admin',
            lastname='User',
            password=bcrypt.generate_password_hash('Admin@1234').decode('utf-8'),  # Default password
            role='ADMIN',  # Ensure this matches your RoleEnum
            status=True
        )
        # Add the user to the session and commit
        db.session.add(default_user)
        db.session.commit()
        print('Default admin user created!')
