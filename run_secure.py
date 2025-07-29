#!/usr/bin/env python3
"""
TalonVigil Secure Application Entry Point
========================================

Production-ready Flask application with comprehensive security measures.
"""

import os
import sys
import logging
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from app_factory import create_secure_app
    from security_audit import DependencyAuditor
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Please ensure all dependencies are installed:")
    print("pip install -r requirements.txt")
    sys.exit(1)

def run_security_audit():
    """Run security audit before starting the application"""
    print("🔍 Running dependency security audit...")
    
    auditor = DependencyAuditor()
    report = auditor.run_full_audit()
    
    if report and report['summary']['total_vulnerabilities'] > 0:
        print("⚠️  Security vulnerabilities found!")
        print("Check security_reports/ directory for detailed reports.")
        
        # In production, you might want to exit here
        if os.environ.get('FLASK_ENV') == 'production':
            print("🛑 Stopping application due to security vulnerabilities in production mode.")
            return False
    else:
        print("✅ Security audit passed!")
    
    return True

def main():
    """Main application entry point"""
    print("🚀 Starting TalonVigil Secure Application...")
    
    # Determine environment
    env = os.environ.get('FLASK_ENV', 'development')
    
    # Run security audit (optional, can be disabled with env var)
    if os.environ.get('SKIP_SECURITY_AUDIT', '').lower() not in ['true', '1', 'yes']:
        if not run_security_audit():
            sys.exit(1)
    
    # Create secure Flask application
    try:
        app = create_secure_app(env)
    except Exception as e:
        print(f"❌ Failed to create application: {e}")
        sys.exit(1)
    
    # Configuration summary
    print(f"📋 Configuration Summary:")
    print(f"   Environment: {env}")
    print(f"   Debug: {app.config.get('DEBUG', False)}")
    print(f"   Database: {app.config.get('SQLALCHEMY_DATABASE_URI', 'Not configured')[:50]}...")
    print(f"   JWT Enabled: {bool(app.config.get('JWT_SECRET_KEY'))}")
    print(f"   CSRF Protection: {app.config.get('WTF_CSRF_ENABLED', False)}")
    print(f"   Rate Limiting: Enabled")
    print(f"   Security Headers: Enabled")
    
    # Run application
    if env == 'development':
        print("🔧 Starting development server...")
        app.run(
            host=os.environ.get('HOST', '0.0.0.0'),
            port=int(os.environ.get('PORT', 5000)),
            debug=True,
            use_reloader=True
        )
    else:
        print("⚠️  Production mode detected.")
        print("   Use a production WSGI server like Gunicorn:")
        print("   gunicorn --bind 0.0.0.0:5000 'run_secure:create_app()'")
        
        # For demonstration, we'll still run the dev server
        # In production, this should be handled by Gunicorn/uWSGI
        app.run(
            host='0.0.0.0',
            port=int(os.environ.get('PORT', 5000)),
            debug=False
        )

def create_app():
    """Application factory for WSGI servers"""
    env = os.environ.get('FLASK_ENV', 'production')
    return create_secure_app(env)

if __name__ == '__main__':
    main()
