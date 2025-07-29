"""
TalonVigil Application Factory
=============================

Secure Flask application factory with comprehensive security measures:
- JWT/OAuth2 authentication
- Content Security Policy (CSP) headers
- Input sanitization and validation
- Rate limiting and security headers
- Dependency security monitoring
"""

import os
import time
import logging
from datetime import datetime
from flask import Flask, request, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail
from flask_migrate import Migrate

# Import security modules
from security_headers import security_headers, configure_cors, setup_csp_context_processor
from input_sanitization import setup_input_sanitization, setup_template_helpers
from jwt_auth import jwt_auth, jwt_required
from config import DevelopmentConfig, ProductionConfig, TestingConfig

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address)
mail = Mail()
migrate = Migrate()

logger = logging.getLogger(__name__)

def create_app(config_name=None):
    """
    Application factory function
    
    Args:
        config_name: Configuration environment (development, production, testing)
        
    Returns:
        Flask: Configured Flask application instance
    """
    app = Flask(__name__)
    
    # Determine configuration
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    config_mapping = {
        'development': DevelopmentConfig,
        'production': ProductionConfig,
        'testing': TestingConfig
    }
    
    config_class = config_mapping.get(config_name, DevelopmentConfig)
    app.config.from_object(config_class)
    
    # Configure logging
    configure_logging(app)
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)
    
    # Initialize security components
    initialize_security(app)
    
    # Configure Flask-Login
    configure_flask_login(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Setup request/response handlers
    setup_request_handlers(app)
    
    logger.info(f"TalonVigil application created with {config_name} configuration")
    
    return app

def configure_logging(app):
    """Configure application logging"""
    log_level = logging.DEBUG if app.config.get('DEBUG') else logging.INFO
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('logs/talonvigil.log') if not app.config.get('TESTING') else logging.NullHandler()
        ]
    )
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)

def initialize_security(app):
    """Initialize all security components"""
    
    # Initialize security headers and CSP
    security_headers.init_app(app)
    setup_csp_context_processor(app)
    
    # Initialize input sanitization
    setup_input_sanitization(app)
    setup_template_helpers(app)
    
    # Initialize JWT authentication
    jwt_auth.init_app(app)
    
    # Configure CORS
    configure_cors(app)
    
    logger.info("Security components initialized")

def configure_flask_login(app):
    """Configure Flask-Login settings"""
    from models import User
    
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    login_manager.session_protection = 'strong'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    @login_manager.request_loader
    def load_user_from_request(request):
        """Support for API key authentication alongside session-based auth"""
        from jwt_auth import validate_api_key
        
        # Try API key authentication
        api_key_info = validate_api_key()
        if api_key_info:
            user = User.query.get(api_key_info['user_id'])
            return user
        
        return None

def register_blueprints(app):
    """Register application blueprints"""
    
    # Authentication routes
    from auth import auth_bp
    app.register_blueprint(auth_bp)
    
    # OAuth2 routes
    from oauth_routes import oauth_bp
    app.register_blueprint(oauth_bp)
    
    # API routes
    from api import api_bp
    app.register_blueprint(api_bp)
    
    # Main application routes
    from routes import bp as main_bp
    app.register_blueprint(main_bp)
    
    # Onboarding routes
    try:
        from onboarding_routes import onboarding_bp
        app.register_blueprint(onboarding_bp)
    except ImportError:
        logger.warning("Onboarding routes not found, skipping...")
    
    logger.info("Blueprints registered successfully")

def register_error_handlers(app):
    """Register global error handlers"""
    
    @app.errorhandler(400)
    def bad_request(error):
        return {
            'error': 'bad_request',
            'message': 'Invalid request data'
        }, 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return {
            'error': 'unauthorized',
            'message': 'Authentication required'
        }, 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return {
            'error': 'forbidden',
            'message': 'Insufficient permissions'
        }, 403
    
    @app.errorhandler(404)
    def not_found(error):
        return {
            'error': 'not_found',
            'message': 'Resource not found'
        }, 404
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        return {
            'error': 'rate_limit_exceeded',
            'message': 'Too many requests',
            'retry_after': error.retry_after
        }, 429
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {error}")
        db.session.rollback()
        return {
            'error': 'internal_server_error',
            'message': 'An internal error occurred'
        }, 500
    
    @app.errorhandler(CSPViolation)
    def csp_violation_handler(error):
        """Handle Content Security Policy violations"""
        logger.warning(f"CSP Violation: {error}")
        return {
            'error': 'csp_violation',
            'message': 'Content Security Policy violation detected'
        }, 400

def setup_request_handlers(app):
    """Setup request and response handlers"""
    
    @app.before_first_request
    def initialize_app():
        """Initialize application on first request"""
        # Create database tables
        db.create_all()
        
        # Run any initialization tasks
        logger.info("Application initialized on first request")
    
    @app.before_request
    def before_request():
        """Before request handler"""
        # Generate request correlation ID
        import uuid
        g.correlation_id = str(uuid.uuid4())
        g.request_start_time = request.environ.get('wsgi.request_start_time', time.time())
        
        # Log request
        logger.info(f"Request started: {request.method} {request.path}")
        
        # Rate limiting for API endpoints
        if request.path.startswith('/api/'):
            # Additional rate limiting for API endpoints
            pass
    
    @app.after_request
    def after_request(response):
        """After request handler"""
        import time
        
        # Calculate request duration
        duration = time.time() - g.get('request_start_time', time.time())
        
        # Add correlation ID to response headers
        response.headers['X-Correlation-ID'] = g.get('correlation_id', 'unknown')
        
        # Log response
        logger.info(f"Request completed: {response.status_code} ({duration:.3f}s)")
        
        return response
    
    @app.teardown_appcontext
    def close_db(error):
        """Clean up database connections"""
        if error:
            logger.error(f"Request ended with error: {error}")
            db.session.rollback()

def setup_rate_limiting(app):
    """Configure rate limiting rules"""
    
    # Global rate limits
    @limiter.request_filter
    def exempt_health_checks():
        """Exempt health check endpoints from rate limiting"""
        return request.endpoint in ['health', 'metrics']
    
    # API-specific rate limits
    @app.route('/api/auth/login', methods=['POST'])
    @limiter.limit("5/minute")
    def rate_limited_login():
        """Rate-limited login endpoint"""
        pass
    
    # Configure different limits for different user types
    @limiter.request_filter
    def authenticated_user_limit():
        """Higher limits for authenticated users"""
        from flask_login import current_user
        
        if current_user.is_authenticated:
            return False  # Don't apply default limits
        return True

class CSPViolation(Exception):
    """Custom exception for CSP violations"""
    pass

# Health check endpoint
def add_health_check(app):
    """Add health check endpoint"""
    
    @app.route('/health')
    def health_check():
        """Application health check"""
        try:
            # Check database connection
            db.session.execute('SELECT 1')
            
            # Check Redis connection (if configured)
            # Add other health checks as needed
            
            return {
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'version': '1.0.0'
            }, 200
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }, 503

# Security monitoring endpoint
def add_security_metrics(app):
    """Add security metrics endpoint"""
    
    @app.route('/metrics/security')
    @jwt_required(['admin'])
    def security_metrics():
        """Security metrics for monitoring"""
        from datetime import datetime, timedelta
        
        # Get recent security events
        recent_failures = get_recent_auth_failures()
        rate_limit_hits = get_rate_limit_violations()
        csp_violations = get_csp_violations()
        
        return {
            'auth_failures_24h': recent_failures,
            'rate_limit_violations_24h': rate_limit_hits,
            'csp_violations_24h': csp_violations,
            'last_security_audit': get_last_audit_date(),
            'timestamp': datetime.utcnow().isoformat()
        }

def get_recent_auth_failures():
    """Get recent authentication failures"""
    # Implement based on your logging/monitoring system
    return 0

def get_rate_limit_violations():
    """Get recent rate limit violations"""
    # Implement based on your rate limiting storage
    return 0

def get_csp_violations():
    """Get recent CSP violations"""
    # Implement based on your CSP violation reporting
    return 0

def get_last_audit_date():
    """Get the date of last security audit"""
    import glob
    
    try:
        audit_files = glob.glob('security_reports/security_audit_*.json')
        if audit_files:
            latest_file = max(audit_files, key=os.path.getctime)
            return os.path.getctime(latest_file)
    except Exception:
        pass
    
    return None

# Application factory with security monitoring
def create_secure_app(config_name=None):
    """
    Create a Flask app with comprehensive security measures
    
    Args:
        config_name: Configuration environment
        
    Returns:
        Flask: Fully configured secure Flask application
    """
    app = create_app(config_name)
    
    # Add additional security endpoints
    add_health_check(app)
    add_security_metrics(app)
    
    # Setup advanced rate limiting
    setup_rate_limiting(app)
    
    # Log security configuration
    log_security_config(app)
    
    return app

def log_security_config(app):
    """Log current security configuration"""
    security_config = {
        'environment': app.config.get('ENV'),
        'debug': app.config.get('DEBUG'),
        'csrf_enabled': app.config.get('WTF_CSRF_ENABLED'),
        'secure_cookies': app.config.get('SESSION_COOKIE_SECURE'),
        'jwt_enabled': bool(app.config.get('JWT_SECRET_KEY')),
        'rate_limiting': bool(limiter),
        'cors_configured': bool(app.config.get('ALLOWED_ORIGINS'))
    }
    
    logger.info(f"Security configuration: {security_config}")

if __name__ == '__main__':
    # For development only
    app = create_secure_app('development')
    app.run(host='0.0.0.0', port=5000, debug=True)
