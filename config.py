import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(16).hex())
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///ticketmanagementsystem.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', 'False') == 'True'
    PROFILE_PIC_STORAGE_FOLDER = os.getenv('PROFILE_PIC_STORAGE_FOLDER', './profiles/')


class DevelopmentConfig(Config):
    DEBUG = True
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')

class ProductionConfig(Config):
    DEBUG = False
    FLASK_ENV = os.getenv('FLASK_ENV', 'production')

    MAIL_DEBUG = True

    # Flask-Mail settings for Gmail
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True') == 'True'
    MAIL_USE_SSL = os.getenv('MAIL_USE_SSL', 'False') == 'True'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME') # Email user
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD') # App specific password
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER')  # Default sender email address
