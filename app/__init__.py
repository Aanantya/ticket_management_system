from flask import Flask
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from app.config import DevelopmentConfig

db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()

load_dotenv()

app = Flask(__name__)

app.config.from_object(DevelopmentConfig)

db.init_app(app)

migrate.init_app(app, db)

bcrypt.init_app(app)

from app import routes

# Create database tables
with app.app_context():
    db.create_all()
