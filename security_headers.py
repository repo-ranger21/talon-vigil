"""
Security Headers and Content Security Policy (CSP) Module
========================================================

Implements comprehensive security headers including CSP to prevent
XSS attacks, clickjacking, and other web vulnerabilities.
"""

from flask import Flask, request, current_app
from flask_talisman import Talisman
import logging

logger = logging.getLogger(__name__)

class SecurityHeaders:
    """Security headers configuration for TalonVigil"""
    
    def __init__(self, app=None):
        self.app = app
        self.talisman = None
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize security headers with Flask app"""
        
        # Content Security Policy configuration
        csp_config = {
            'default-src': "'self'",
            'script-src': [
                "'self'",
                "'unsafe-inline'",  # Remove this in production, use nonces instead
                'https://cdn.jsdelivr.net',
                'https://cdnjs.cloudflare.com',
                'https://code.jquery.com',
                'https://stackpath.bootstrapcdn.com'
            ],
            'style-src': [
                "'self'",
                "'unsafe-inline'",  # Required for Bootstrap and dynamic styles
                'https://cdn.jsdelivr.net',
                'https://cdnjs.cloudflare.com',
                'https://stackpath.bootstrapcdn.com',
                'https://fonts.googleapis.com'
            ],
            'font-src': [
                "'self'",
                'https://cdn.jsdelivr.net',
                'https://cdnjs.cloudflare.com',
                'https://fonts.gstatic.com',
                'data:'
            ],
            'img-src': [
                "'self'",
                'data:',
                'https:',
                'blob:'
            ],
            'connect-src': [
                "'self'",
                'https://api.virustotal.com',
                'https://api.abuseipdb.com',
                'wss:',  # For WebSocket connections
                'ws:'   # Development WebSocket
            ],
            'frame-src': "'none'",
            'frame-ancestors': "'none'",
            'object-src': "'none'",
            'base-uri': "'self'",
            'form-action': "'self'",
            'upgrade-insecure-requests': True if app.config.get('ENV') == 'production' else False
        }
        
        # Additional security headers
        force_https = app.config.get('ENV') == 'production'
        
        # Initialize Talisman with comprehensive security headers
        self.talisman = Talisman(
            app,
            force_https=force_https,
            strict_transport_security=True,
            strict_transport_security_max_age=31536000,
            strict_transport_security_include_subdomains=True,
            strict_transport_security_preload=True,
            content_security_policy=csp_config,
            content_security_policy_report_only=False,
            content_security_policy_report_uri=None,
            referrer_policy='strict-origin-when-cross-origin',
            feature_policy={
                'accelerometer': "'none'",
                'camera': "'none'",
                'geolocation': "'none'",
                'gyroscope': "'none'",
                'magnetometer': "'none'",
                'microphone': "'none'",
                'payment': "'none'",
                'usb': "'none'"
            },
            permissions_policy={
                'accelerometer': '()',
                'camera': '()',
                'geolocation': '()',
                'gyroscope': '()',
                'magnetometer': '()',
                'microphone': '()',
                'payment': '()',
                'usb': '()'
            }
        )
        
        # Custom after_request handler for additional headers
        @app.after_request
        def add_custom_security_headers(response):
            """Add custom security headers to all responses"""
            
            # Prevent MIME type sniffing
            response.headers['X-Content-Type-Options'] = 'nosniff'
            
            # Enable XSS protection (legacy browsers)
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            # Prevent clickjacking
            response.headers['X-Frame-Options'] = 'DENY'
            
            # Don't expose server information
            response.headers.pop('Server', None)
            
            # Cache control for sensitive pages
            if request.endpoint and any(sensitive in request.endpoint for sensitive in 
                                      ['auth', 'admin', 'api', 'dashboard']):
                response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                response.headers['Pragma'] = 'no-cache'
                response.headers['Expires'] = '0'
            
            # CORS headers for API endpoints
            if request.path.startswith('/api/'):
                origin = request.headers.get('Origin')
                allowed_origins = app.config.get('ALLOWED_ORIGINS', [])
                
                if origin in allowed_origins or app.config.get('ENV') == 'development':
                    response.headers['Access-Control-Allow-Origin'] = origin or '*'
                    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
                    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-API-Key, X-Correlation-ID'
                    response.headers['Access-Control-Allow-Credentials'] = 'true'
                    response.headers['Access-Control-Max-Age'] = '3600'
            
            return response
        
        logger.info("Security headers initialized successfully")

def create_nonce():
    """
    Generate a cryptographically secure nonce for CSP
    This should be used in templates to allow specific inline scripts/styles
    """
    import secrets
    return secrets.token_urlsafe(16)

def get_csp_nonce():
    """Get CSP nonce for current request"""
    if not hasattr(request, '_csp_nonce'):
        request._csp_nonce = create_nonce()
    return request._csp_nonce

# Production-ready CSP configuration (stricter)
PRODUCTION_CSP_CONFIG = {
    'default-src': "'self'",
    'script-src': [
        "'self'",
        "'nonce-{nonce}'",  # Use nonces instead of unsafe-inline
        'https://cdn.jsdelivr.net',
        'https://cdnjs.cloudflare.com'
    ],
    'style-src': [
        "'self'",
        "'nonce-{nonce}'",
        'https://cdn.jsdelivr.net',
        'https://cdnjs.cloudflare.com',
        'https://fonts.googleapis.com'
    ],
    'font-src': [
        "'self'",
        'https://fonts.gstatic.com',
        'data:'
    ],
    'img-src': [
        "'self'",
        'data:',
        'https:'
    ],
    'connect-src': [
        "'self'",
        'https://api.virustotal.com',
        'https://api.abuseipdb.com'
    ],
    'frame-src': "'none'",
    'frame-ancestors': "'none'",
    'object-src': "'none'",
    'base-uri': "'self'",
    'form-action': "'self'",
    'upgrade-insecure-requests': True
}

def configure_production_csp(app):
    """Configure stricter CSP for production environment"""
    if app.config.get('ENV') == 'production':
        # Update CSP to use nonces
        @app.before_request
        def inject_csp_nonce():
            request.csp_nonce = create_nonce()
        
        # Update Talisman CSP config
        nonce_csp = PRODUCTION_CSP_CONFIG.copy()
        for directive in ['script-src', 'style-src']:
            if directive in nonce_csp:
                nonce_csp[directive] = [
                    source.format(nonce=get_csp_nonce()) if '{nonce}' in source else source
                    for source in nonce_csp[directive]
                ]
        
        app.extensions['talisman'].content_security_policy = nonce_csp
        logger.info("Production CSP with nonces configured")

# Template context processor to make nonce available in templates
def setup_csp_context_processor(app):
    """Add CSP nonce to template context"""
    @app.context_processor
    def inject_csp_nonce():
        return dict(csp_nonce=get_csp_nonce() if hasattr(request, '_csp_nonce') else create_nonce())

# CORS configuration for different environments
def configure_cors(app):
    """Configure CORS based on environment"""
    from flask_cors import CORS
    
    if app.config.get('ENV') == 'production':
        # Strict CORS for production
        allowed_origins = app.config.get('ALLOWED_ORIGINS', [
            'https://threatcompass.yourdomain.com',
            'https://app.threatcompass.com'
        ])
        
        CORS(app,
             origins=allowed_origins,
             methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
             allow_headers=['Content-Type', 'Authorization', 'X-API-Key', 'X-Correlation-ID'],
             expose_headers=['X-Total-Count', 'X-Rate-Limit-Remaining'],
             supports_credentials=True,
             max_age=3600)
    else:
        # More permissive for development
        CORS(app, 
             origins=['http://localhost:3000', 'http://localhost:5000', 'http://127.0.0.1:5000'],
             supports_credentials=True)
    
    logger.info(f"CORS configured for {app.config.get('ENV', 'development')} environment")

# Global security headers instance
security_headers = SecurityHeaders()
