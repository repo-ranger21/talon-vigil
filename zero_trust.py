"""
Zero Trust Architecture Implementation
====================================

Implements Zero Trust security model with Azure AD integration,
conditional access policies, and identity-based access controls.
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from functools import wraps
import jwt
import requests
from flask import Flask, request, jsonify, g, current_app
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin
from flask_security.utils import hash_password, verify_password
from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
import msal

logger = logging.getLogger(__name__)

class ZeroTrustAuth:
    """Zero Trust Authentication and Authorization Engine"""
    
    def __init__(self, app: Flask = None):
        self.app = app
        self.credential = None
        self.graph_client = None
        self.conditional_access_policies = {}
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize Zero Trust authentication with Flask app"""
        self.app = app
        
        # Initialize Azure credentials
        try:
            # Use managed identity in Azure, fallback to default credential
            self.credential = ManagedIdentityCredential() if app.config.get('AZURE_CLIENT_ID') else DefaultAzureCredential()
            logger.info("Azure credentials initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Azure credentials: {e}")
            raise
        
        # Initialize Microsoft Graph client
        self._init_graph_client()
        
        # Load conditional access policies
        self._load_conditional_access_policies()
        
        # Set up Zero Trust middleware
        self._setup_zero_trust_middleware()
    
    def _init_graph_client(self):
        """Initialize Microsoft Graph client for Azure AD operations"""
        try:
            tenant_id = self.app.config['AZURE_TENANT_ID']
            client_id = self.app.config['AZURE_CLIENT_ID']
            client_secret = self.app.config.get('AZURE_CLIENT_SECRET')
            
            # Create MSAL confidential client application
            authority = f"https://login.microsoftonline.com/{tenant_id}"
            
            if client_secret:
                self.graph_client = msal.ConfidentialClientApplication(
                    client_id=client_id,
                    client_credential=client_secret,
                    authority=authority
                )
            else:
                # Use managed identity
                self.graph_client = msal.PublicClientApplication(
                    client_id=client_id,
                    authority=authority
                )
                
            logger.info("Microsoft Graph client initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize Graph client: {e}")
            raise
    
    def _load_conditional_access_policies(self):
        """Load conditional access policies from Azure AD"""
        try:
            # Default conditional access policies
            self.conditional_access_policies = {
                'mfa_required_locations': [
                    'external_networks',
                    'unknown_locations'
                ],
                'device_compliance_required': True,
                'sign_in_risk_policy': {
                    'low_risk': 'allow',
                    'medium_risk': 'mfa_required',
                    'high_risk': 'block'
                },
                'user_risk_policy': {
                    'low_risk': 'allow',
                    'medium_risk': 'password_change_required',
                    'high_risk': 'block'
                },
                'application_enforcement': {
                    'require_approved_apps': True,
                    'require_app_protection_policy': True
                }
            }
            
            logger.info("Conditional access policies loaded")
            
        except Exception as e:
            logger.error(f"Failed to load conditional access policies: {e}")
    
    def _setup_zero_trust_middleware(self):
        """Set up Zero Trust middleware for request validation"""
        
        @self.app.before_request
        def validate_zero_trust_requirements():
            """Validate Zero Trust requirements for each request"""
            
            # Skip validation for health checks and static files
            if request.endpoint in ['health', 'static']:
                return
            
            # Extract authentication information
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                if request.endpoint not in ['auth.login', 'auth.register']:
                    return jsonify({
                        'error': 'authentication_required',
                        'message': 'Zero Trust policy requires authentication'
                    }), 401
                return
            
            # Validate JWT token and extract claims
            token = auth_header.split(' ', 1)[1]
            try:
                claims = self._validate_azure_ad_token(token)
                if not claims:
                    return jsonify({
                        'error': 'invalid_token',
                        'message': 'Invalid or expired token'
                    }), 401
                
                # Store claims in Flask g context
                g.user_claims = claims
                g.user_id = claims.get('sub')
                g.tenant_id = claims.get('tid')
                g.object_id = claims.get('oid')
                
                # Validate conditional access requirements
                validation_result = self._validate_conditional_access(claims, request)
                if not validation_result['allowed']:
                    return jsonify({
                        'error': 'conditional_access_denied',
                        'message': validation_result['reason'],
                        'required_actions': validation_result.get('required_actions', [])
                    }), 403
                
            except Exception as e:
                logger.error(f"Zero Trust validation failed: {e}")
                return jsonify({
                    'error': 'validation_failed',
                    'message': 'Zero Trust validation failed'
                }), 500
    
    def _validate_azure_ad_token(self, token: str) -> Optional[Dict]:
        """Validate Azure AD JWT token"""
        try:
            # Get Azure AD public keys for token validation
            jwks_url = f"https://login.microsoftonline.com/{self.app.config['AZURE_TENANT_ID']}/discovery/v2.0/keys"
            jwks_response = requests.get(jwks_url, timeout=10)
            jwks = jwks_response.json()
            
            # Decode token header to get key ID
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get('kid')
            
            # Find the matching public key
            public_key = None
            for key in jwks['keys']:
                if key['kid'] == kid:
                    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
                    break
            
            if not public_key:
                logger.error("No matching public key found for token")
                return None
            
            # Verify and decode token
            claims = jwt.decode(
                token,
                public_key,
                algorithms=['RS256'],
                audience=self.app.config['AZURE_CLIENT_ID'],
                issuer=f"https://login.microsoftonline.com/{self.app.config['AZURE_TENANT_ID']}/v2.0"
            )
            
            return claims
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            return None
    
    def _validate_conditional_access(self, claims: Dict, request) -> Dict:
        """Validate conditional access policies"""
        try:
            # Extract relevant information from claims
            user_id = claims.get('oid')
            tenant_id = claims.get('tid')
            auth_methods = claims.get('amr', [])
            device_id = claims.get('deviceid')
            ip_address = request.remote_addr
            
            # Check MFA requirement
            if not self._is_mfa_satisfied(auth_methods, ip_address):
                return {
                    'allowed': False,
                    'reason': 'Multi-factor authentication required',
                    'required_actions': ['mfa_enrollment', 'mfa_verification']
                }
            
            # Check device compliance
            if self.conditional_access_policies.get('device_compliance_required'):
                if not self._is_device_compliant(device_id):
                    return {
                        'allowed': False,
                        'reason': 'Device compliance required',
                        'required_actions': ['device_enrollment', 'compliance_check']
                    }
            
            # Check sign-in risk
            sign_in_risk = self._assess_sign_in_risk(claims, request)
            risk_policy = self.conditional_access_policies['sign_in_risk_policy']
            
            if sign_in_risk == 'high' and risk_policy['high_risk'] == 'block':
                return {
                    'allowed': False,
                    'reason': 'High sign-in risk detected',
                    'required_actions': ['security_verification', 'admin_approval']
                }
            
            # Check user risk
            user_risk = self._assess_user_risk(user_id)
            user_risk_policy = self.conditional_access_policies['user_risk_policy']
            
            if user_risk == 'high' and user_risk_policy['high_risk'] == 'block':
                return {
                    'allowed': False,
                    'reason': 'High user risk detected',
                    'required_actions': ['password_reset', 'security_review']
                }
            
            # All checks passed
            return {'allowed': True, 'reason': 'All policies satisfied'}
            
        except Exception as e:
            logger.error(f"Conditional access validation failed: {e}")
            return {
                'allowed': False,
                'reason': 'Policy validation error',
                'required_actions': ['retry_authentication']
            }
    
    def _is_mfa_satisfied(self, auth_methods: List[str], ip_address: str) -> bool:
        """Check if MFA requirements are satisfied"""
        # Check if MFA was used in authentication
        mfa_methods = {'mfa', 'phone', 'sms', 'oath', 'app'}
        has_mfa = bool(set(auth_methods) & mfa_methods)
        
        # Check if location requires MFA
        location_risk = self._assess_location_risk(ip_address)
        mfa_required_locations = self.conditional_access_policies['mfa_required_locations']
        
        if location_risk in mfa_required_locations:
            return has_mfa
        
        return True  # MFA not required for trusted locations
    
    def _is_device_compliant(self, device_id: str) -> bool:
        """Check device compliance status"""
        if not device_id:
            return False
        
        try:
            # In a real implementation, this would query Microsoft Graph API
            # For now, we'll simulate device compliance check
            
            # Example compliance checks:
            # - Device is managed by Intune
            # - Device meets compliance policies
            # - Device has required security updates
            
            # Simulate compliance check (replace with actual Graph API call)
            return True
            
        except Exception as e:
            logger.error(f"Device compliance check failed: {e}")
            return False
    
    def _assess_sign_in_risk(self, claims: Dict, request) -> str:
        """Assess sign-in risk level"""
        try:
            risk_factors = []
            
            # Check for unusual location
            ip_address = request.remote_addr
            if self._is_unusual_location(claims.get('oid'), ip_address):
                risk_factors.append('unusual_location')
            
            # Check for suspicious user agent
            user_agent = request.headers.get('User-Agent', '')
            if self._is_suspicious_user_agent(user_agent):
                risk_factors.append('suspicious_user_agent')
            
            # Check time of access
            current_hour = datetime.utcnow().hour
            if current_hour < 6 or current_hour > 22:  # Outside business hours
                risk_factors.append('unusual_time')
            
            # Check for rapid successive logins
            if self._detect_rapid_logins(claims.get('oid')):
                risk_factors.append('rapid_logins')
            
            # Calculate risk level
            if len(risk_factors) >= 3:
                return 'high'
            elif len(risk_factors) >= 1:
                return 'medium'
            else:
                return 'low'
                
        except Exception as e:
            logger.error(f"Sign-in risk assessment failed: {e}")
            return 'medium'  # Default to medium risk on error
    
    def _assess_user_risk(self, user_id: str) -> str:
        """Assess user risk level"""
        try:
            # In a real implementation, this would consider:
            # - Recent security incidents
            # - Unusual activity patterns
            # - Compromised credentials reports
            # - Azure AD Identity Protection signals
            
            # Simulate user risk assessment
            return 'low'
            
        except Exception as e:
            logger.error(f"User risk assessment failed: {e}")
            return 'medium'
    
    def _assess_location_risk(self, ip_address: str) -> str:
        """Assess location risk based on IP address"""
        try:
            # In a real implementation, this would:
            # - Query IP geolocation services
            # - Check against known trusted networks
            # - Compare with user's typical locations
            
            # For now, classify all external IPs as external_networks
            if not self._is_internal_ip(ip_address):
                return 'external_networks'
            
            return 'trusted_location'
            
        except Exception as e:
            logger.error(f"Location risk assessment failed: {e}")
            return 'unknown_locations'
    
    def _is_internal_ip(self, ip_address: str) -> bool:
        """Check if IP address is from internal network"""
        # Define internal IP ranges
        internal_ranges = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8'
        ]
        
        # In a real implementation, use ipaddress module for proper checking
        return ip_address.startswith(('10.', '172.', '192.168.', '127.'))
    
    def _is_unusual_location(self, user_id: str, ip_address: str) -> bool:
        """Check if location is unusual for the user"""
        # In a real implementation, this would check user's location history
        return False
    
    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent appears suspicious"""
        suspicious_patterns = [
            'curl', 'wget', 'python-requests', 'bot', 'crawler'
        ]
        return any(pattern in user_agent.lower() for pattern in suspicious_patterns)
    
    def _detect_rapid_logins(self, user_id: str) -> bool:
        """Detect rapid successive login attempts"""
        # In a real implementation, this would check login history
        return False

def require_zero_trust(roles: Optional[List[str]] = None, permissions: Optional[List[str]] = None):
    """
    Decorator to enforce Zero Trust requirements
    
    Args:
        roles: Required roles for access
        permissions: Required permissions for access
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if user is authenticated
            if not hasattr(g, 'user_claims'):
                return jsonify({
                    'error': 'authentication_required',
                    'message': 'Zero Trust authentication required'
                }), 401
            
            # Check role requirements
            if roles:
                user_roles = g.user_claims.get('roles', [])
                if not any(role in user_roles for role in roles):
                    return jsonify({
                        'error': 'insufficient_roles',
                        'message': f'Required roles: {roles}',
                        'user_roles': user_roles
                    }), 403
            
            # Check permission requirements
            if permissions:
                user_permissions = g.user_claims.get('permissions', [])
                if not all(perm in user_permissions for perm in permissions):
                    missing_perms = [p for p in permissions if p not in user_permissions]
                    return jsonify({
                        'error': 'insufficient_permissions',
                        'message': f'Missing permissions: {missing_perms}'
                    }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

class ConditionalAccessPolicy:
    """Conditional Access Policy Management"""
    
    def __init__(self):
        self.policies = {}
    
    def create_policy(self, name: str, conditions: Dict, actions: Dict) -> str:
        """Create a new conditional access policy"""
        policy_id = f"policy_{len(self.policies) + 1}"
        
        self.policies[policy_id] = {
            'name': name,
            'conditions': conditions,
            'actions': actions,
            'created_at': datetime.utcnow(),
            'enabled': True
        }
        
        logger.info(f"Created conditional access policy: {name}")
        return policy_id
    
    def evaluate_policies(self, context: Dict) -> Dict:
        """Evaluate all policies against the given context"""
        results = {
            'allowed': True,
            'applied_policies': [],
            'required_actions': []
        }
        
        for policy_id, policy in self.policies.items():
            if not policy['enabled']:
                continue
            
            if self._evaluate_conditions(policy['conditions'], context):
                results['applied_policies'].append(policy_id)
                
                # Apply policy actions
                actions = policy['actions']
                if actions.get('block'):
                    results['allowed'] = False
                    results['block_reason'] = policy['name']
                
                if actions.get('require_mfa'):
                    results['required_actions'].append('mfa_required')
                
                if actions.get('require_compliant_device'):
                    results['required_actions'].append('device_compliance_required')
        
        return results
    
    def _evaluate_conditions(self, conditions: Dict, context: Dict) -> bool:
        """Evaluate policy conditions against context"""
        # User conditions
        if 'users' in conditions:
            user_condition = conditions['users']
            if user_condition.get('include'):
                if context.get('user_id') not in user_condition['include']:
                    return False
            if user_condition.get('exclude'):
                if context.get('user_id') in user_condition['exclude']:
                    return False
        
        # Location conditions
        if 'locations' in conditions:
            location_condition = conditions['locations']
            user_location = context.get('location')
            if location_condition.get('include'):
                if user_location not in location_condition['include']:
                    return False
            if location_condition.get('exclude'):
                if user_location in location_condition['exclude']:
                    return False
        
        # Risk conditions
        if 'sign_in_risk' in conditions:
            risk_levels = conditions['sign_in_risk']
            user_risk = context.get('sign_in_risk', 'low')
            if user_risk not in risk_levels:
                return False
        
        return True

# Global Zero Trust instance
zero_trust = ZeroTrustAuth()
