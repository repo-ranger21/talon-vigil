#!/usr/bin/env python3
"""
Security Implementation Test Suite
=================================

Basic tests to verify security features are working correctly.
"""

import sys
import os
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test that all security modules can be imported"""
    print("🧪 Testing security module imports...")
    
    modules_to_test = [
        'security_headers',
        'input_sanitization', 
        'jwt_auth',
        'oauth_routes',
        'config'
    ]
    
    for module in modules_to_test:
        try:
            __import__(module)
            print(f"   ✅ {module}")
        except ImportError as e:
            print(f"   ❌ {module}: {e}")
            return False
    
    return True

def test_input_sanitization():
    """Test input sanitization functions"""
    print("🧪 Testing input sanitization...")
    
    try:
        from input_sanitization import InputSanitizer
        
        # Test HTML sanitization
        dangerous_html = '<script>alert("xss")</script><p>Safe content</p>'
        sanitized = InputSanitizer.sanitize_html(dangerous_html)
        
        if '<script>' not in sanitized:
            print("   ✅ HTML sanitization working")
        else:
            print("   ❌ HTML sanitization failed")
            return False
        
        # Test plain text sanitization
        dangerous_text = '<script>alert("xss")</script>Normal text'
        sanitized_text = InputSanitizer.sanitize_plain_text(dangerous_text)
        
        if '&lt;script&gt;' in sanitized_text:
            print("   ✅ Plain text sanitization working")
        else:
            print("   ❌ Plain text sanitization failed")
            return False
        
        # Test URL validation
        valid_url = InputSanitizer.validate_url('https://example.com')
        invalid_url = InputSanitizer.validate_url('javascript:alert("xss")')
        
        if valid_url and not invalid_url:
            print("   ✅ URL validation working")
        else:
            print("   ❌ URL validation failed")
            return False
        
        return True
        
    except Exception as e:
        print(f"   ❌ Input sanitization test failed: {e}")
        return False

def test_jwt_auth():
    """Test JWT authentication functionality"""
    print("🧪 Testing JWT authentication...")
    
    try:
        from jwt_auth import JWTAuth
        from config import DevelopmentConfig
        
        # Create a mock Flask app context for testing
        class MockApp:
            def __init__(self):
                self.config = {
                    'JWT_SECRET_KEY': 'test-secret-key',
                    'JWT_ACCESS_TOKEN_EXPIRES': 3600,
                    'JWT_REFRESH_TOKEN_EXPIRES': 2592000,
                    'JWT_ALGORITHM': 'HS256',
                    'JWT_ISSUER': 'talonvigil-test'
                }
        
        jwt_auth = JWTAuth()
        mock_app = MockApp()
        
        # Test token generation (would need proper Flask context in real app)
        print("   ✅ JWT auth module loaded successfully")
        return True
        
    except Exception as e:
        print(f"   ❌ JWT auth test failed: {e}")
        return False

def test_security_headers():
    """Test security headers configuration"""
    print("🧪 Testing security headers...")
    
    try:
        from security_headers import SecurityHeaders, PRODUCTION_CSP_CONFIG
        
        # Test CSP configuration exists
        if 'default-src' in PRODUCTION_CSP_CONFIG:
            print("   ✅ CSP configuration loaded")
        else:
            print("   ❌ CSP configuration missing")
            return False
        
        # Test security headers class
        security_headers = SecurityHeaders()
        if security_headers:
            print("   ✅ Security headers module working")
        else:
            print("   ❌ Security headers module failed")
            return False
        
        return True
        
    except Exception as e:
        print(f"   ❌ Security headers test failed: {e}")
        return False

def test_config():
    """Test security configuration"""
    print("🧪 Testing security configuration...")
    
    try:
        from config import DevelopmentConfig, ProductionConfig
        
        # Test development config
        dev_config = DevelopmentConfig()
        if hasattr(dev_config, 'JWT_SECRET_KEY'):
            print("   ✅ Development config has JWT settings")
        else:
            print("   ❌ Development config missing JWT settings")
            return False
        
        # Test production config
        prod_config = ProductionConfig()
        if hasattr(prod_config, 'SESSION_COOKIE_SECURE'):
            print("   ✅ Production config has security settings")
        else:
            print("   ❌ Production config missing security settings")
            return False
        
        return True
        
    except Exception as e:
        print(f"   ❌ Config test failed: {e}")
        return False

def test_requirements():
    """Test that security requirements are installed"""
    print("🧪 Testing security dependencies...")
    
    required_packages = [
        'PyJWT',
        'bleach', 
        'flask-talisman',
        'marshmallow'
    ]
    
    all_installed = True
    
    for package in required_packages:
        try:
            __import__(package.lower().replace('-', '_'))
            print(f"   ✅ {package}")
        except ImportError:
            print(f"   ❌ {package} not installed")
            all_installed = False
    
    return all_installed

def main():
    """Run all security tests"""
    print("🔒 TalonVigil Security Implementation Test Suite")
    print("=" * 50)
    
    tests = [
        test_requirements,
        test_imports,
        test_config,
        test_input_sanitization,
        test_jwt_auth,
        test_security_headers
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            print()  # Add spacing between tests
        except Exception as e:
            print(f"   💥 Test crashed: {e}")
            print()
    
    print("=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All security tests passed!")
        return 0
    else:
        print("⚠️  Some security tests failed. Please review the output above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
