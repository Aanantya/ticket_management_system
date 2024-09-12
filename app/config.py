import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(16).hex())
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///ticketmanagementsystem.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', 'False') == 'True'
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    PROFILE_PIC_STORAGE_FOLDER = os.getenv('PROFILE_PIC_STORAGE_FOLDER', './profiles/')


class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
    # Flask-Mail settings for Gmail
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587  # Port for TLS
    MAIL_USERNAME = 'your-email@gmail.com'  # Your Gmail address
    MAIL_PASSWORD = 'your-app-password'  # Your Gmail App Password
    MAIL_USE_TLS = True  # Use TLS
    MAIL_USE_SSL = False  # Do not use SSL
    MAIL_DEFAULT_SENDER = 'your-email@gmail.com'  # Default sender email address