import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(16).hex())
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///ticketmanagementsystem.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', 'False') == 'True'
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    