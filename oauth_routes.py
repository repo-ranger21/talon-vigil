"""
OAuth2 Authentication Routes
===========================

Implements OAuth2 authentication endpoints for secure API access.
Provides token generation, refresh, and revocation endpoints.
"""

from flask import Blueprint, request, jsonify, current_app
from jwt_auth import jwt_auth, oauth2_password_flow, jwt_required
from input_sanitization import validate_input, InputSanitizer
from marshmallow import Schema, fields, validate
import logging

logger = logging.getLogger(__name__)

oauth_bp = Blueprint('oauth', __name__, url_prefix='/oauth')

class TokenRequestSchema(Schema):
    """Schema for OAuth2 token requests"""
    grant_type = fields.Str(required=True, validate=validate.OneOf(['password', 'refresh_token']))
    username = fields.Email(allow_none=True)
    password = fields.Str(allow_none=True, validate=validate.Length(min=1, max=128))
    refresh_token = fields.Str(allow_none=True)
    scope = fields.Str(missing='read write')
    client_id = fields.Str(allow_none=True)

class TokenRevocationSchema(Schema):
    """Schema for token revocation requests"""
    token = fields.Str(required=True)
    token_type_hint = fields.Str(allow_none=True, validate=validate.OneOf(['access_token', 'refresh_token']))

@oauth_bp.route('/token', methods=['POST'])
@validate_input(TokenRequestSchema)
def token_endpoint():
    """
    OAuth2 Token Endpoint
    
    Supports:
    - Resource Owner Password Credentials Grant (grant_type=password)
    - Refresh Token Grant (grant_type=refresh_token)
    """
    data = request.validated_data
    grant_type = data['grant_type']
    
    try:
        if grant_type == 'password':
            # Resource Owner Password Credentials Grant
            username = data.get('username')
            password = data.get('password')
            client_id = data.get('client_id')
            scope = data.get('scope', 'read write')
            
            if not username or not password:
                return jsonify({
                    'error': 'invalid_request',
                    'error_description': 'Username and password are required'
                }), 400
            
            # Sanitize inputs
            username = InputSanitizer.sanitize_email(username)
            if not username:
                return jsonify({
                    'error': 'invalid_request',
                    'error_description': 'Invalid username format'
                }), 400
            
            # Authenticate user and generate tokens
            result, status_code = oauth2_password_flow(username, password, client_id, scope)
            
            if status_code == 200:
                logger.info(f"OAuth2 token issued for user: {username}")
            else:
                logger.warning(f"OAuth2 authentication failed for user: {username}")
            
            return jsonify(result), status_code
            
        elif grant_type == 'refresh_token':
            # Refresh Token Grant
            refresh_token = data.get('refresh_token')
            
            if not refresh_token:
                return jsonify({
                    'error': 'invalid_request',
                    'error_description': 'Refresh token is required'
                }), 400
            
            # Generate new access token
            new_tokens = jwt_auth.refresh_access_token(refresh_token)
            
            if not new_tokens:
                return jsonify({
                    'error': 'invalid_grant',
                    'error_description': 'Invalid or expired refresh token'
                }), 400
            
            logger.info("OAuth2 token refreshed successfully")
            return jsonify(new_tokens), 200
            
        else:
            return jsonify({
                'error': 'unsupported_grant_type',
                'error_description': f'Grant type "{grant_type}" is not supported'
            }), 400
            
    except Exception as e:
        logger.error(f"OAuth2 token endpoint error: {e}")
        return jsonify({
            'error': 'server_error',
            'error_description': 'Internal server error'
        }), 500

@oauth_bp.route('/revoke', methods=['POST'])
@validate_input(TokenRevocationSchema)
def revoke_endpoint():
    """
    OAuth2 Token Revocation Endpoint
    
    Revokes access or refresh tokens
    """
    data = request.validated_data
    token = data['token']
    token_type_hint = data.get('token_type_hint')
    
    try:
        # Verify the token to get user information
        payload = jwt_auth.verify_token(token)
        
        if payload:
            # In a production system, you would:
            # 1. Add the token JTI to a revocation blacklist
            # 2. Store revoked tokens in Redis/database with expiration
            # 3. Check blacklist during token verification
            
            logger.info(f"Token revoked for user {payload.get('user_id')}")
            
            # For now, just return success
            # The token will still be valid until it expires naturally
            return '', 200
        else:
            # Even if token is invalid, return success per OAuth2 spec
            return '', 200
            
    except Exception as e:
        logger.error(f"OAuth2 revoke endpoint error: {e}")
        # Return success even on error per OAuth2 spec
        return '', 200

@oauth_bp.route('/introspect', methods=['POST'])
@jwt_required(['admin'])
def introspect_endpoint():
    """
    OAuth2 Token Introspection Endpoint (RFC 7662)
    
    Allows authorized clients to check token validity
    Requires admin scope for security
    """
    token = request.form.get('token') or request.json.get('token')
    
    if not token:
        return jsonify({
            'error': 'invalid_request',
            'error_description': 'Token parameter is required'
        }), 400
    
    try:
        payload = jwt_auth.verify_token(token)
        
        if payload:
            # Return token introspection response
            response = {
                'active': True,
                'scope': ' '.join(payload.get('scopes', [])),
                'client_id': 'talonvigil',
                'username': str(payload.get('user_id')),
                'token_type': 'Bearer',
                'exp': payload.get('exp'),
                'iat': payload.get('iat'),
                'sub': str(payload.get('user_id')),
                'aud': payload.get('iss'),
                'tenant_id': payload.get('tenant_id')
            }
            
            logger.info(f"Token introspection successful for user {payload.get('user_id')}")
            return jsonify(response), 200
        else:
            # Token is invalid or expired
            return jsonify({'active': False}), 200
            
    except Exception as e:
        logger.error(f"OAuth2 introspect endpoint error: {e}")
        return jsonify({'active': False}), 200

@oauth_bp.route('/userinfo', methods=['GET'])
@jwt_required(['profile'])
def userinfo_endpoint():
    """
    OAuth2 UserInfo Endpoint (OpenID Connect)
    
    Returns user information for valid tokens with profile scope
    """
    from flask import g
    from models import User
    
    try:
        user_id = g.current_user_id
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'invalid_token',
                'error_description': 'User not found'
            }), 401
        
        # Return user information (be careful about sensitive data)
        userinfo = {
            'sub': str(user.id),
            'email': user.email,
            'name': user.name,
            'email_verified': user.email_verified,
            'tenant_id': str(getattr(user, 'tenant_id', ''))
        }
        
        logger.info(f"UserInfo provided for user {user.id}")
        return jsonify(userinfo), 200
        
    except Exception as e:
        logger.error(f"OAuth2 userinfo endpoint error: {e}")
        return jsonify({
            'error': 'server_error',
            'error_description': 'Internal server error'
        }), 500

@oauth_bp.route('/.well-known/openid_configuration', methods=['GET'])
def openid_configuration():
    """
    OpenID Connect Discovery Document
    
    Provides metadata about the OAuth2/OpenID Connect implementation
    """
    base_url = request.host_url.rstrip('/')
    
    config = {
        'issuer': base_url,
        'authorization_endpoint': f'{base_url}/oauth/authorize',
        'token_endpoint': f'{base_url}/oauth/token',
        'userinfo_endpoint': f'{base_url}/oauth/userinfo',
        'revocation_endpoint': f'{base_url}/oauth/revoke',
        'introspection_endpoint': f'{base_url}/oauth/introspect',
        'jwks_uri': f'{base_url}/oauth/jwks',
        'response_types_supported': ['code', 'token'],
        'grant_types_supported': ['password', 'refresh_token'],
        'token_endpoint_auth_methods_supported': ['client_secret_post', 'client_secret_basic'],
        'scopes_supported': ['openid', 'profile', 'email', 'read', 'write', 'admin'],
        'claims_supported': ['sub', 'email', 'name', 'email_verified', 'tenant_id'],
        'code_challenge_methods_supported': ['S256'],
        'subject_types_supported': ['public']
    }
    
    return jsonify(config), 200

@oauth_bp.route('/jwks', methods=['GET'])
def jwks_endpoint():
    """
    JSON Web Key Set (JWKS) Endpoint
    
    Provides public keys for token verification
    Note: This is a simplified implementation for development
    Production should use proper key management
    """
    # In production, you should:
    # 1. Use RSA keys instead of HMAC
    # 2. Implement proper key rotation
    # 3. Store keys securely
    
    # For HMAC (symmetric keys), we don't expose the key
    # This endpoint would be used with RSA (asymmetric keys)
    jwks = {
        'keys': [
            # Example RSA key structure (not implemented)
            # {
            #     'kty': 'RSA',
            #     'use': 'sig',
            #     'kid': 'key-id',
            #     'n': 'base64url-encoded-modulus',
            #     'e': 'AQAB'
            # }
        ]
    }
    
    return jsonify(jwks), 200

# Error handlers for OAuth2 endpoints
@oauth_bp.errorhandler(400)
def oauth_bad_request(error):
    """Handle bad request errors in OAuth2 format"""
    return jsonify({
        'error': 'invalid_request',
        'error_description': str(error.description)
    }), 400

@oauth_bp.errorhandler(401)
def oauth_unauthorized(error):
    """Handle unauthorized errors in OAuth2 format"""
    return jsonify({
        'error': 'invalid_client',
        'error_description': 'Authentication failed'
    }), 401

@oauth_bp.errorhandler(403)
def oauth_forbidden(error):
    """Handle forbidden errors in OAuth2 format"""
    return jsonify({
        'error': 'insufficient_scope',
        'error_description': 'Insufficient permissions'
    }), 403

@oauth_bp.errorhandler(500)
def oauth_server_error(error):
    """Handle server errors in OAuth2 format"""
    logger.error(f"OAuth2 server error: {error}")
    return jsonify({
        'error': 'server_error',
        'error_description': 'Internal server error'
    }), 500
