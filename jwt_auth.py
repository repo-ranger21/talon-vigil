"""
JWT Authentication Module for TalonVigil
========================================

Provides JWT token generation, validation, and secure API access.
Implements OAuth2-like flow with proper token management.
"""

import jwt
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify, current_app, g
from flask_login import current_user
from werkzeug.security import check_password_hash
from models import User, APIKey
from db_manager import db
import logging

logger = logging.getLogger(__name__)

class JWTAuth:
    """JWT Authentication handler for TalonVigil"""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize JWT authentication with Flask app"""
        app.config.setdefault('JWT_SECRET_KEY', secrets.token_urlsafe(32))
        app.config.setdefault('JWT_ACCESS_TOKEN_EXPIRES', timedelta(hours=1))
        app.config.setdefault('JWT_REFRESH_TOKEN_EXPIRES', timedelta(days=30))
        app.config.setdefault('JWT_ALGORITHM', 'HS256')
        app.config.setdefault('JWT_ISSUER', 'talonvigil')
    
    def generate_tokens(self, user_id, tenant_id=None, scopes=None):
        """
        Generate JWT access and refresh tokens
        
        Args:
            user_id: User ID
            tenant_id: Tenant ID (optional)
            scopes: List of permission scopes
            
        Returns:
            dict: Contains access_token, refresh_token, expires_in
        """
        if scopes is None:
            scopes = ['read', 'write']
        
        now = datetime.now(timezone.utc)
        access_expires = now + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
        refresh_expires = now + current_app.config['JWT_REFRESH_TOKEN_EXPIRES']
        
        # Access token payload
        access_payload = {
            'user_id': user_id,
            'tenant_id': tenant_id,
            'scopes': scopes,
            'type': 'access',
            'iat': now,
            'exp': access_expires,
            'iss': current_app.config['JWT_ISSUER'],
            'jti': secrets.token_urlsafe(16)  # JWT ID for token revocation
        }
        
        # Refresh token payload
        refresh_payload = {
            'user_id': user_id,
            'tenant_id': tenant_id,
            'type': 'refresh',
            'iat': now,
            'exp': refresh_expires,
            'iss': current_app.config['JWT_ISSUER'],
            'jti': secrets.token_urlsafe(16)
        }
        
        try:
            access_token = jwt.encode(
                access_payload,
                current_app.config['JWT_SECRET_KEY'],
                algorithm=current_app.config['JWT_ALGORITHM']
            )
            
            refresh_token = jwt.encode(
                refresh_payload,
                current_app.config['JWT_SECRET_KEY'],
                algorithm=current_app.config['JWT_ALGORITHM']
            )
            
            return {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'token_type': 'Bearer',
                'expires_in': int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()),
                'scope': ' '.join(scopes)
            }
            
        except Exception as e:
            logger.error(f"JWT token generation failed: {e}")
            return None
    
    def verify_token(self, token):
        """
        Verify and decode JWT token
        
        Args:
            token: JWT token string
            
        Returns:
            dict: Decoded payload or None if invalid
        """
        try:
            payload = jwt.decode(
                token,
                current_app.config['JWT_SECRET_KEY'],
                algorithms=[current_app.config['JWT_ALGORITHM']],
                issuer=current_app.config['JWT_ISSUER']
            )
            
            # Check if token is expired
            if datetime.fromtimestamp(payload['exp'], timezone.utc) < datetime.now(timezone.utc):
                return None
                
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {e}")
            return None
        except Exception as e:
            logger.error(f"JWT token verification failed: {e}")
            return None
    
    def refresh_access_token(self, refresh_token):
        """
        Generate new access token from refresh token
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            dict: New token data or None if invalid
        """
        payload = self.verify_token(refresh_token)
        
        if not payload or payload.get('type') != 'refresh':
            return None
        
        # Generate new access token with same user/tenant
        return self.generate_tokens(
            user_id=payload['user_id'],
            tenant_id=payload.get('tenant_id'),
            scopes=payload.get('scopes', ['read', 'write'])
        )

# Global JWT auth instance
jwt_auth = JWTAuth()

def jwt_required(scopes=None):
    """
    Decorator to require JWT authentication
    
    Args:
        scopes: Required scopes (list of strings)
    """
    if scopes is None:
        scopes = []
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Extract token from Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({
                    'error': 'missing_token',
                    'message': 'Authorization header with Bearer token required'
                }), 401
            
            token = auth_header.split(' ', 1)[1]
            payload = jwt_auth.verify_token(token)
            
            if not payload:
                return jsonify({
                    'error': 'invalid_token',
                    'message': 'Invalid or expired token'
                }), 401
            
            # Check token type
            if payload.get('type') != 'access':
                return jsonify({
                    'error': 'wrong_token_type',
                    'message': 'Access token required'
                }), 401
            
            # Check required scopes
            token_scopes = payload.get('scopes', [])
            for scope in scopes:
                if scope not in token_scopes:
                    return jsonify({
                        'error': 'insufficient_scope',
                        'message': f'Scope "{scope}" required'
                    }), 403
            
            # Store user info in Flask g context
            g.current_user_id = payload['user_id']
            g.tenant_id = payload.get('tenant_id')
            g.token_scopes = token_scopes
            g.jwt_payload = payload
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def oauth2_password_flow(username, password, client_id=None, scope=None):
    """
    OAuth2 Resource Owner Password Credentials Grant
    
    Args:
        username: User email/username
        password: User password
        client_id: Client identifier (optional)
        scope: Requested scopes (space-separated string)
        
    Returns:
        dict: Token response or error
    """
    # Validate user credentials
    user = User.query.filter_by(email=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return {
            'error': 'invalid_grant',
            'error_description': 'Invalid username or password'
        }, 400
    
    # Check if user is active
    if not user.is_active:
        return {
            'error': 'invalid_grant',
            'error_description': 'User account is disabled'
        }, 400
    
    # Parse requested scopes
    requested_scopes = scope.split() if scope else ['read', 'write']
    
    # For now, grant all requested scopes (in production, validate against user permissions)
    granted_scopes = requested_scopes
    
    # Generate tokens
    tokens = jwt_auth.generate_tokens(
        user_id=user.id,
        tenant_id=getattr(user, 'tenant_id', None),
        scopes=granted_scopes
    )
    
    if not tokens:
        return {
            'error': 'server_error',
            'error_description': 'Failed to generate tokens'
        }, 500
    
    logger.info(f"OAuth2 tokens generated for user {user.id}")
    
    return tokens, 200

def validate_api_key():
    """
    Validate API key from request headers
    Used as fallback authentication method
    
    Returns:
        dict: User info if valid, None otherwise
    """
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return None
    
    # Look up API key in database
    key_record = APIKey.query.filter_by(key_hash=api_key, is_active=True).first()
    if not key_record:
        return None
    
    # Check if key is expired
    if key_record.expires_at and key_record.expires_at < datetime.utcnow():
        return None
    
    # Return user info
    return {
        'user_id': key_record.user_id,
        'tenant_id': key_record.tenant_id,
        'scopes': key_record.scopes or ['read']
    }

def hybrid_auth_required(scopes=None):
    """
    Decorator that accepts both JWT tokens and API keys
    
    Args:
        scopes: Required scopes (list of strings)
    """
    if scopes is None:
        scopes = []
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_info = None
            
            # Try JWT authentication first
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ', 1)[1]
                payload = jwt_auth.verify_token(token)
                
                if payload and payload.get('type') == 'access':
                    auth_info = {
                        'user_id': payload['user_id'],
                        'tenant_id': payload.get('tenant_id'),
                        'scopes': payload.get('scopes', []),
                        'auth_type': 'jwt'
                    }
            
            # Fallback to API key authentication
            if not auth_info:
                api_key_info = validate_api_key()
                if api_key_info:
                    auth_info = {**api_key_info, 'auth_type': 'api_key'}
            
            # Check if authentication succeeded
            if not auth_info:
                return jsonify({
                    'error': 'authentication_required',
                    'message': 'Valid JWT token or API key required'
                }), 401
            
            # Check required scopes
            user_scopes = auth_info.get('scopes', [])
            for scope in scopes:
                if scope not in user_scopes:
                    return jsonify({
                        'error': 'insufficient_scope',
                        'message': f'Scope "{scope}" required'
                    }), 403
            
            # Store auth info in Flask g context
            g.current_user_id = auth_info['user_id']
            g.tenant_id = auth_info.get('tenant_id')
            g.auth_scopes = user_scopes
            g.auth_type = auth_info['auth_type']
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
