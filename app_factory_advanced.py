"""
Advanced Flask Application Factory for TalonVigil
===============================================

Creates a production-ready Flask application with:
- Zero Trust Architecture
- Advanced Security Features
- AI-Powered Threat Intelligence
- DevSecOps Integration
- SOAR Automation
- Observability & Monitoring
"""

import os
import logging
from datetime import datetime
from typing import Optional

from flask import Flask, request, g, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_mail import Mail
from flask_cors import CORS

# Import custom modules
from config import DevelopmentConfig, ProductionConfig, TestingConfig
from security_headers import security_headers, configure_cors
from input_sanitization import setup_input_sanitization
from zero_trust import zero_trust
from opentelemetry_config import setup_opentelemetry
from models import db, User, Role, user_datastore
from threat_intelligence import ThreatIntelligenceEngine
from adaptive_scoring import AdaptiveThreatScoring
from soar_integration import SOAROrchestrator
from chaos_engineering import ChaosTestRunner
from compliance_framework import ComplianceManager

# Import blueprints
from api import api_bp
from auth import auth_bp
from oauth_routes import oauth_bp
from threat_intel_routes import threat_intel_bp
from soar_routes import soar_bp
from compliance_routes import compliance_bp
from chaos_routes import chaos_bp

logger = logging.getLogger(__name__)

# Global extensions
db = SQLAlchemy()
security = Security()
jwt = JWTManager()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)
migrate = Migrate()
mail = Mail()

def create_app(config_name: str = 'development') -> Flask:
    """
    Create and configure Flask application with advanced security features
    
    Args:
        config_name: Configuration environment ('development', 'production', 'testing')
        
    Returns:
        Configured Flask application
    """
    app = Flask(__name__)
    
    # Load configuration
    config_map = {
        'development': DevelopmentConfig,
        'production': ProductionConfig,
        'testing': TestingConfig
    }
    
    app.config.from_object(config_map.get(config_name, DevelopmentConfig))
    
    # Add Azure and advanced configurations
    _configure_azure_integration(app)
    _configure_advanced_security(app)
    _configure_ai_features(app)
    
    # Initialize extensions
    _initialize_extensions(app)
    
    # Set up security features
    _setup_security_features(app)
    
    # Register blueprints
    _register_blueprints(app)
    
    # Set up monitoring and observability
    _setup_observability(app)
    
    # Initialize AI and threat intelligence
    _initialize_ai_components(app)
    
    logger.info(f"TalonVigil application created successfully in {config_name} mode")
    return app

def _configure_azure_integration(app: Flask) -> None:
    """Configure Azure services integration"""
    # Azure AD and authentication
    app.config.update({
        'AZURE_TENANT_ID': os.environ.get('AZURE_TENANT_ID'),
        'AZURE_CLIENT_ID': os.environ.get('AZURE_CLIENT_ID'),
        'AZURE_CLIENT_SECRET': os.environ.get('AZURE_CLIENT_SECRET'),
        'AZURE_KEY_VAULT_URL': os.environ.get('AZURE_KEY_VAULT_URL'),
        'AZURE_STORAGE_ACCOUNT': os.environ.get('AZURE_STORAGE_ACCOUNT'),
        'AZURE_RESOURCE_GROUP': os.environ.get('AZURE_RESOURCE_GROUP'),
        'AZURE_SUBSCRIPTION_ID': os.environ.get('AZURE_SUBSCRIPTION_ID')
    })
    
    # Azure Monitor and Application Insights
    app.config.update({
        'APPLICATIONINSIGHTS_CONNECTION_STRING': os.environ.get('APPLICATIONINSIGHTS_CONNECTION_STRING'),
        'AZURE_MONITOR_ENDPOINT': os.environ.get('AZURE_MONITOR_ENDPOINT')
    })

def _configure_advanced_security(app: Flask) -> None:
    """Configure advanced security settings"""
    # Flask-Security configuration
    app.config.update({
        'SECURITY_REGISTERABLE': True,
        'SECURITY_RECOVERABLE': True,
        'SECURITY_TRACKABLE': True,
        'SECURITY_CHANGEABLE': True,
        'SECURITY_CONFIRMABLE': True,
        'SECURITY_PASSWORD_HASH': 'bcrypt',
        'SECURITY_PASSWORD_SALT': os.environ.get('SECURITY_PASSWORD_SALT', 'your-salt-here'),
        'SECURITY_TWO_FACTOR': True,
        'SECURITY_TWO_FACTOR_REQUIRED': app.config.get('ENV') == 'production',
        'SECURITY_WEBAUTHN': True,
        'SECURITY_OAUTH_ENABLE': True
    })
    
    # Advanced JWT configuration
    app.config.update({
        'JWT_BLACKLIST_ENABLED': True,
        'JWT_BLACKLIST_TOKEN_CHECKS': ['access', 'refresh'],
        'JWT_ACCESS_TOKEN_EXPIRES': app.config.get('JWT_ACCESS_TOKEN_EXPIRES'),
        'JWT_REFRESH_TOKEN_EXPIRES': app.config.get('JWT_REFRESH_TOKEN_EXPIRES')
    })

def _configure_ai_features(app: Flask) -> None:
    """Configure AI and ML features"""
    app.config.update({
        'AI_MODEL_PATH': os.environ.get('AI_MODEL_PATH', './models'),
        'THREAT_INTEL_API_KEYS': {
            'virustotal': os.environ.get('VIRUSTOTAL_API_KEY'),
            'abuseipdb': os.environ.get('ABUSEIPDB_API_KEY'),
            'shodan': os.environ.get('SHODAN_API_KEY'),
            'greynoise': os.environ.get('GREYNOISE_API_KEY')
        },
        'ML_FEDERATION_ENABLED': os.environ.get('ML_FEDERATION_ENABLED', 'false').lower() == 'true',
        'MITRE_ATTACK_DATA_PATH': os.environ.get('MITRE_ATTACK_DATA_PATH', './data/mitre'),
        'ADAPTIVE_SCORING_ENABLED': True
    })

def _initialize_extensions(app: Flask) -> None:
    """Initialize Flask extensions"""
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    limiter.init_app(app)
    
    # Initialize Flask-Security
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security.init_app(app, user_datastore)
    
    # Initialize JWT
    jwt.init_app(app)
    
    # Configure CORS
    configure_cors(app)

def _setup_security_features(app: Flask) -> None:
    """Set up comprehensive security features"""
    # Initialize security headers and CSP
    security_headers.init_app(app)
    
    # Set up input sanitization
    setup_input_sanitization(app)
    
    # Initialize Zero Trust architecture
    zero_trust.init_app(app)
    
    # Set up security event handlers
    _setup_security_handlers(app)

def _setup_security_handlers(app: Flask) -> None:
    """Set up security event handlers"""
    
    @app.before_request
    def security_before_request():
        """Security checks before each request"""
        # Track request for security monitoring
        g.request_start_time = datetime.utcnow()
        g.request_id = request.headers.get('X-Request-ID', 'unknown')
        
        # Log security-relevant events
        if request.endpoint and 'admin' in request.endpoint:
            logger.info(f"Admin access attempt: {request.remote_addr} -> {request.endpoint}")
    
    @app.after_request
    def security_after_request(response):
        """Security processing after each request"""
        # Add correlation ID
        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id
        
        # Log response for security monitoring
        if hasattr(g, 'request_start_time'):
            duration = (datetime.utcnow() - g.request_start_time).total_seconds()
            if duration > 5.0:  # Log slow requests
                logger.warning(f"Slow request: {request.endpoint} took {duration:.2f}s")
        
        return response
    
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        """Check if JWT token has been revoked"""
        # In production, check against Redis blacklist
        jti = jwt_payload['jti']
        # For now, return False (no tokens are revoked)
        return False

def _register_blueprints(app: Flask) -> None:
    """Register application blueprints"""
    # Core API blueprints
    app.register_blueprint(api_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(oauth_bp)
    
    # Advanced feature blueprints
    app.register_blueprint(threat_intel_bp)
    app.register_blueprint(soar_bp)
    app.register_blueprint(compliance_bp)
    app.register_blueprint(chaos_bp)

def _setup_observability(app: Flask) -> None:
    """Set up comprehensive observability"""
    # Initialize OpenTelemetry
    setup_opentelemetry(app)
    
    # Set up health check endpoints
    @app.route('/health')
    def health_check():
        """Application health check"""
        try:
            # Check database connectivity
            db.session.execute('SELECT 1')
            
            # Check Redis connectivity
            from redis import Redis
            redis_client = Redis.from_url(app.config['CELERY_BROKER_URL'])
            redis_client.ping()
            
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'version': '2.0.0',
                'components': {
                    'database': 'healthy',
                    'redis': 'healthy',
                    'ai_engine': 'healthy'
                }
            }), 200
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return jsonify({
                'status': 'unhealthy',
                'timestamp': datetime.utcnow().isoformat(),
                'error': str(e)
            }), 503
    
    @app.route('/metrics')
    def metrics():
        """Prometheus metrics endpoint"""
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

def _initialize_ai_components(app: Flask) -> None:
    """Initialize AI and threat intelligence components"""
    with app.app_context():
        # Initialize threat intelligence engine
        threat_engine = ThreatIntelligenceEngine(app)
        app.threat_engine = threat_engine
        
        # Initialize adaptive scoring system
        scoring_engine = AdaptiveThreatScoring(app)
        app.scoring_engine = scoring_engine
        
        # Initialize SOAR orchestrator
        soar_orchestrator = SOAROrchestrator(app)
        app.soar_orchestrator = soar_orchestrator
        
        # Initialize chaos testing
        chaos_runner = ChaosTestRunner(app)
        app.chaos_runner = chaos_runner
        
        # Initialize compliance manager
        compliance_manager = ComplianceManager(app)
        app.compliance_manager = compliance_manager
        
        logger.info("AI and advanced components initialized successfully")

def create_celery(app: Flask):
    """Create Celery instance for background tasks"""
    from celery import Celery
    
    celery = Celery(
        app.import_name,
        backend=app.config['CELERY_RESULT_BACKEND'],
        broker=app.config['CELERY_BROKER_URL']
    )
    
    celery.conf.update(app.config)
    
    class ContextTask(celery.Task):
        """Make celery tasks work with Flask app context"""
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    return celery

# CLI commands for management
def register_cli_commands(app: Flask) -> None:
    """Register CLI commands for application management"""
    
    @app.cli.command()
    def init_db():
        """Initialize database with default data"""
        from models import init_default_data
        db.create_all()
        init_default_data()
        print("Database initialized successfully")
    
    @app.cli.command()
    def run_security_audit():
        """Run comprehensive security audit"""
        from security_audit import DependencyAuditor
        auditor = DependencyAuditor()
        report = auditor.run_full_audit()
        print(f"Security audit completed. Check security_reports/ for details.")
    
    @app.cli.command()
    def train_ml_models():
        """Train machine learning models"""
        if hasattr(app, 'threat_engine'):
            app.threat_engine.train_models()
            print("ML models training initiated")
        else:
            print("Threat engine not initialized")
    
    @app.cli.command()
    def run_chaos_test():
        """Run chaos engineering tests"""
        if hasattr(app, 'chaos_runner'):
            app.chaos_runner.run_scheduled_tests()
            print("Chaos tests initiated")
        else:
            print("Chaos runner not initialized")

# Error handlers
def register_error_handlers(app: Flask) -> None:
    """Register application error handlers"""
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Resource not found'}), 404
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({'error': 'Access forbidden'}), 403
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({'error': 'Authentication required'}), 401
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {error}")
        return jsonify({'error': 'Internal server error'}), 500

# Application factory for different environments
def create_development_app():
    """Create development application"""
    app = create_app('development')
    register_cli_commands(app)
    register_error_handlers(app)
    return app

def create_production_app():
    """Create production application"""
    app = create_app('production')
    register_error_handlers(app)
    return app

def create_testing_app():
    """Create testing application"""
    app = create_app('testing')
    register_cli_commands(app)
    register_error_handlers(app)
    return app
