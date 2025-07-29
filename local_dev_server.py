#!/usr/bin/env python3
"""
TalonVigil Local Development Server
=================================

Flask development server for TalonVigil cybersecurity intelligence platform.
Serves templates, static files, and provides API endpoints for testing.
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from datetime import datetime
import os
import json

# Initialize Flask application
app = Flask(__name__)
app.secret_key = 'talonvigil-dev-secret-key-change-in-production'

# Configuration
app.config['DEBUG'] = True
app.config['TEMPLATES_AUTO_RELOAD'] = True

# ==============================================================================
# MAIN ROUTES
# ==============================================================================

@app.route('/')
def index():
    """Homepage with hero section and overview"""
    try:
        return render_template('index.html')
    except:
        # Fallback if template doesn't exist
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>TalonVigil - Cybersecurity Intelligence Platform</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: white;
                }
                .container { text-align: center; max-width: 800px; padding: 2rem; }
                h1 { font-size: 3rem; margin-bottom: 1rem; }
                .subtitle { font-size: 1.2rem; margin-bottom: 2rem; opacity: 0.9; }
                .nav { margin-top: 2rem; }
                .nav a { 
                    color: white; 
                    text-decoration: none; 
                    margin: 0 1rem; 
                    padding: 0.5rem 1rem;
                    border: 1px solid rgba(255,255,255,0.3);
                    border-radius: 5px;
                    transition: all 0.3s;
                }
                .nav a:hover { background: rgba(255,255,255,0.1); }
                .status { 
                    margin-top: 2rem; 
                    padding: 1rem; 
                    background: rgba(255,255,255,0.1); 
                    border-radius: 10px; 
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ TalonVigil</h1>
                <p class="subtitle">Cybersecurity Intelligence Platform</p>
                <p>Advanced threat detection and response system</p>
                
                <div class="nav">
                    <a href="/features">Features</a>
                    <a href="/pricing">Pricing</a>
                    <a href="/about">About</a>
                    <a href="/contact">Contact</a>
                    <a href="/login">Login</a>
                </div>
                
                <div class="status">
                    <h3>✅ TalonVigil Development Server Active</h3>
                    <p>Server Time: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
                    <p>Status: Operational</p>
                </div>
            </div>
        </body>
        </html>
        """

@app.route('/features')
def features():
    """Features page"""
    return render_template('features.html') if os.path.exists('templates/features.html') else jsonify({
        'page': 'features',
        'features': [
            'Real-time threat detection',
            'Advanced analytics',
            'Incident response automation',
            'Threat intelligence integration',
            'Security orchestration',
            'Compliance monitoring'
        ]
    })

@app.route('/pricing')
def pricing():
    """Pricing page"""
    return render_template('pricing.html') if os.path.exists('templates/pricing.html') else jsonify({
        'page': 'pricing',
        'plans': [
            {'name': 'Starter', 'price': '$29/month', 'features': ['Basic monitoring', 'Email alerts']},
            {'name': 'Pro', 'price': '$99/month', 'features': ['Advanced analytics', 'API access', '24/7 support']},
            {'name': 'Enterprise', 'price': 'Custom', 'features': ['Full platform', 'Custom integration', 'Dedicated support']}
        ]
    })

@app.route('/about')
def about():
    """About page"""
    return render_template('about.html') if os.path.exists('templates/about.html') else jsonify({
        'page': 'about',
        'company': 'TalonVigil',
        'mission': 'Protecting organizations with advanced cybersecurity intelligence',
        'founded': '2024',
        'focus': 'Threat detection and response automation'
    })

@app.route('/contact')
def contact():
    """Contact page"""
    return render_template('contact.html') if os.path.exists('templates/contact.html') else jsonify({
        'page': 'contact',
        'email': 'contact@talonvigil.com',
        'phone': '+1-555-TALON-01',
        'address': 'TalonVigil HQ, Cybersecurity District'
    })

@app.route('/login')
def login():
    """Login page"""
    return render_template('auth/login.html') if os.path.exists('templates/auth/login.html') else """
    <!DOCTYPE html>
    <html><head><title>TalonVigil Login</title>
    <style>
        body { font-family: Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
               min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-form { background: white; padding: 2rem; border-radius: 10px; max-width: 400px; width: 100%; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
        button { width: 100%; padding: 10px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background: #764ba2; }
    </style></head>
    <body>
        <div class="login-form">
            <h2>🛡️ TalonVigil Login</h2>
            <form action="/api/auth/login" method="post">
                <input type="email" placeholder="Email" name="email" required>
                <input type="password" placeholder="Password" name="password" required>
                <button type="submit">Sign In</button>
            </form>
            <p><a href="/">← Back to Home</a></p>
        </div>
    </body></html>
    """

@app.route('/register')
def register():
    """Registration page"""
    return render_template('auth/register.html') if os.path.exists('templates/auth/register.html') else jsonify({
        'page': 'register',
        'message': 'Registration form - redirect to signup page'
    })

@app.route('/dashboard')
def dashboard():
    """Dashboard page"""
    dashboard_data = {
        'user': 'Demo User',
        'timestamp': datetime.now().isoformat(),
        'threat_summary': {
            'total_indicators': 1247,
            'last_update': '2 minutes ago',
            'federated_nodes': 7
        },
        'alerts': {
            'critical': 3,
            'high': 8,
            'medium': 15,
            'low': 23
        },
        'incidents': {
            'active': 12,
            'resolved_today': 8
        },
        'recent_alerts': [
            {
                'time': '14:35',
                'severity': 'Critical',
                'source': 'Firewall',
                'description': 'Multiple failed authentication attempts detected',
                'status': 'Investigating'
            }
        ]
    }
    return render_template('dashboard.html', data=dashboard_data) if os.path.exists('templates/dashboard.html') else jsonify(dashboard_data)

# ==============================================================================
# API ENDPOINTS
# ==============================================================================

@app.route('/api/health')
def api_health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'TalonVigil API',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """Login API endpoint"""
    email = request.form.get('email') or request.json.get('email') if request.is_json else None
    password = request.form.get('password') or request.json.get('password') if request.is_json else None
    
    # Demo authentication
    if email and password:
        return jsonify({
            'status': 'success',
            'message': 'Login successful (demo)',
            'user': {'email': email, 'role': 'analyst'},
            'token': 'demo-jwt-token-12345'
        })
    else:
        return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

@app.route('/api/threats')
def api_threats():
    """Threat data API"""
    return jsonify({
        'threats': [
            {'id': 1, 'type': 'malware', 'severity': 'high', 'status': 'active'},
            {'id': 2, 'type': 'phishing', 'severity': 'medium', 'status': 'contained'},
            {'id': 3, 'type': 'ddos', 'severity': 'critical', 'status': 'investigating'}
        ],
        'total': 3,
        'timestamp': datetime.now().isoformat()
    })

# ==============================================================================
# ERROR HANDLERS
# ==============================================================================

@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return jsonify({
        'error': '404 Not Found',
        'message': 'The requested resource was not found',
        'available_endpoints': [
            '/', '/features', '/pricing', '/about', '/contact', 
            '/login', '/register', '/dashboard', '/api/health'
        ]
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    return jsonify({
        'error': '500 Internal Server Error',
        'message': 'An internal server error occurred'
    }), 500

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

if __name__ == '__main__':
    print("🚀 Starting TalonVigil Development Server...")
    print("📊 Configuration:")
    print(f"   - Debug mode: {app.config['DEBUG']}")
    print(f"   - Templates auto-reload: {app.config['TEMPLATES_AUTO_RELOAD']}")
    print(f"   - Working directory: {os.getcwd()}")
    
    # Check for templates directory
    if os.path.exists('templates'):
        print("   ✅ Templates directory found")
        template_count = len([f for f in os.listdir('templates') if f.endswith('.html')])
        print(f"   📄 Templates available: {template_count}")
    else:
        print("   ⚠️ Templates directory not found - using fallback HTML")
    
    # Check for static files
    if os.path.exists('static'):
        print("   ✅ Static files directory found")
    else:
        print("   ⚠️ Static files directory not found")
    
    print("\n🌐 Access URLs:")
    print("   - Local: http://localhost:3000")
    print("   - Network: http://0.0.0.0:3000")
    print("\n🛡️ TalonVigil ready for testing!")
    
    # Start the development server
    app.run(
        host='0.0.0.0',
        port=3000,
        debug=True,
        use_reloader=True
    )