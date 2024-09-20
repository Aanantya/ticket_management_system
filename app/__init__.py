import os
from flask import Flask
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_login import LoginManager
from config import DevelopmentConfig, ProductionConfig

# Load environment variables
load_dotenv()

# Flask extensions
db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
mail = Mail()
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

def create_app():
    from app.create_admin import create_default_user

    app = Flask(__name__)
    app.config.from_object(DevelopmentConfig)

    # Initialize Flask extensions
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)

    # Register tms blueprint
    from app.routes import tms
    app.register_blueprint(tms)

    # Create database tables
    with app.app_context():
        db.create_all()
        create_default_user()  # Create default user

    return app