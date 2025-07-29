import os
import secrets
from datetime import timedelta

class Config:
    # Basic Flask configuration
    SECRET_KEY = os.environ.get("FLASK_APP_SECRET_KEY", "dev-secret-unsafe")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///threatcompass.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Celery configuration
    CELERY_BROKER_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
    CELERY_RESULT_BACKEND = os.environ.get("REDIS_URL", "redis://redis:6379/0")
    
    # JWT configuration
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", secrets.token_urlsafe(32))
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_ALGORITHM = 'HS256'
    JWT_ISSUER = 'talonvigil'
    
    # Security configuration
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = os.environ.get("REDIS_URL", "redis://redis:6379/1")
    RATELIMIT_DEFAULT = "100/hour"
    
    # CORS configuration
    ALLOWED_ORIGINS = []
    
    # File upload security
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'csv', 'json'}

class DevelopmentConfig(Config):
    DEBUG = True
    ENV = 'development'
    
    # Less strict security for development
    SESSION_COOKIE_SECURE = False
    ALLOWED_ORIGINS = [
        'http://localhost:3000',
        'http://localhost:5000',
        'http://127.0.0.1:5000'
    ]
    
    # Development JWT settings
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)  # Longer for development

class ProductionConfig(Config):
    DEBUG = False
    ENV = 'production'
    
    # Production security settings
    SECRET_KEY = os.environ.get("FLASK_APP_SECRET_KEY")
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
    
    if not SECRET_KEY:
        raise ValueError("FLASK_APP_SECRET_KEY environment variable must be set in production")
    if not JWT_SECRET_KEY:
        raise ValueError("JWT_SECRET_KEY environment variable must be set in production")
    
    # Strict CORS for production
    ALLOWED_ORIGINS = [
        os.environ.get("FRONTEND_URL", "https://threatcompass.yourdomain.com")
    ]
    
    # Production database
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
    if not SQLALCHEMY_DATABASE_URI:
        raise ValueError("DATABASE_URL environment variable must be set in production")
    
    # Enhanced security headers
    FORCE_HTTPS = True
    SESSION_COOKIE_DOMAIN = os.environ.get("SESSION_COOKIE_DOMAIN")

class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    ENV = 'testing'
    
    # In-memory database for testing
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False
    
    # Shorter token expiration for testing
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=5)
    
    # Test-specific settings
    SESSION_COOKIE_SECURE = False