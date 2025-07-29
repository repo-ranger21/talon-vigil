"""
Input Sanitization Module
========================

Provides comprehensive input sanitization to prevent XSS, SQL injection,
and other injection attacks. Never use dangerouslySetInnerHTML equivalent.
"""

import bleach
import html
import re
import logging
from urllib.parse import urlparse
from flask import request, abort
from functools import wraps
from marshmallow import Schema, fields, validate, ValidationError

logger = logging.getLogger(__name__)

class InputSanitizer:
    """Input sanitization and validation utilities"""
    
    # Allowed HTML tags for rich text content (very restrictive)
    ALLOWED_TAGS = [
        'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote'
    ]
    
    # Allowed HTML attributes
    ALLOWED_ATTRIBUTES = {
        '*': ['class'],
        'a': ['href', 'title'],
        'abbr': ['title'],
        'acronym': ['title']
    }
    
    # Protocols allowed in links
    ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']
    
    @staticmethod
    def sanitize_html(text, allowed_tags=None, allowed_attributes=None):
        """
        Sanitize HTML content to prevent XSS attacks
        
        Args:
            text: Input text to sanitize
            allowed_tags: List of allowed HTML tags
            allowed_attributes: Dict of allowed attributes per tag
            
        Returns:
            str: Sanitized HTML content
        """
        if not text:
            return ''
        
        if allowed_tags is None:
            allowed_tags = InputSanitizer.ALLOWED_TAGS
        
        if allowed_attributes is None:
            allowed_attributes = InputSanitizer.ALLOWED_ATTRIBUTES
        
        try:
            # Clean HTML with bleach
            cleaned = bleach.clean(
                text,
                tags=allowed_tags,
                attributes=allowed_attributes,
                protocols=InputSanitizer.ALLOWED_PROTOCOLS,
                strip=True
            )
            
            # Additional escaping for safety
            return html.escape(cleaned, quote=True)
            
        except Exception as e:
            logger.error(f"HTML sanitization failed: {e}")
            # Fallback to complete HTML escaping
            return html.escape(text, quote=True)
    
    @staticmethod
    def sanitize_plain_text(text, max_length=None):
        """
        Sanitize plain text input
        
        Args:
            text: Input text to sanitize
            max_length: Maximum allowed length
            
        Returns:
            str: Sanitized plain text
        """
        if not text:
            return ''
        
        # Convert to string and strip whitespace
        text = str(text).strip()
        
        # Escape HTML entities
        text = html.escape(text, quote=True)
        
        # Remove control characters except tabs, newlines, and carriage returns
        text = ''.join(char for char in text if ord(char) >= 32 or char in '\t\n\r')
        
        # Truncate if necessary
        if max_length and len(text) > max_length:
            text = text[:max_length]
        
        return text
    
    @staticmethod
    def sanitize_sql_identifier(identifier):
        """
        Sanitize SQL identifiers (table names, column names)
        
        Args:
            identifier: SQL identifier to sanitize
            
        Returns:
            str: Sanitized identifier
        """
        if not identifier:
            return ''
        
        # Only allow alphanumeric characters and underscores
        sanitized = re.sub(r'[^a-zA-Z0-9_]', '', str(identifier))
        
        # Ensure it starts with a letter or underscore
        if sanitized and not sanitized[0].isalpha() and sanitized[0] != '_':
            sanitized = '_' + sanitized
        
        return sanitized[:64]  # Limit length
    
    @staticmethod
    def sanitize_filename(filename):
        """
        Sanitize file names for safe storage
        
        Args:
            filename: Original filename
            
        Returns:
            str: Sanitized filename
        """
        if not filename:
            return 'unnamed_file'
        
        # Remove path traversal attempts
        filename = filename.replace('..', '').replace('/', '').replace('\\', '')
        
        # Keep only safe characters
        filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
        
        # Ensure reasonable length
        if len(filename) > 255:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            filename = name[:250] + ('.' + ext if ext else '')
        
        return filename
    
    @staticmethod
    def validate_url(url, allowed_schemes=None):
        """
        Validate and sanitize URLs
        
        Args:
            url: URL to validate
            allowed_schemes: List of allowed URL schemes
            
        Returns:
            str: Validated URL or None if invalid
        """
        if not url:
            return None
        
        if allowed_schemes is None:
            allowed_schemes = ['http', 'https']
        
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in allowed_schemes:
                return None
            
            # Check for dangerous characters
            if any(char in url for char in ['<', '>', '"', "'", '`']):
                return None
            
            # Reconstruct URL to normalize it
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
        except Exception as e:
            logger.warning(f"URL validation failed for {url}: {e}")
            return None
    
    @staticmethod
    def sanitize_email(email):
        """
        Sanitize and validate email addresses
        
        Args:
            email: Email address to sanitize
            
        Returns:
            str: Sanitized email or None if invalid
        """
        if not email:
            return None
        
        email = str(email).strip().lower()
        
        # Basic email regex (not comprehensive, use proper validation library for production)
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if re.match(email_pattern, email) and len(email) <= 254:
            return email
        
        return None

# Input validation schemas using Marshmallow
class IOCValidationSchema(Schema):
    """Validation schema for IOC (Indicator of Compromise) data"""
    ioc_type = fields.Str(required=True, validate=validate.OneOf(['ip', 'domain', 'url', 'hash', 'email']))
    value = fields.Str(required=True, validate=validate.Length(min=1, max=500))
    description = fields.Str(allow_none=True, validate=validate.Length(max=1000))
    source = fields.Str(allow_none=True, validate=validate.Length(max=100))
    confidence = fields.Int(validate=validate.Range(min=0, max=100), missing=50)
    tags = fields.List(fields.Str(validate=validate.Length(max=50)), missing=[])

class UserRegistrationSchema(Schema):
    """Validation schema for user registration"""
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=8, max=128))
    name = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    company = fields.Str(allow_none=True, validate=validate.Length(max=200))

class PlaybookSchema(Schema):
    """Validation schema for playbook data"""
    name = fields.Str(required=True, validate=validate.Length(min=1, max=200))
    description = fields.Str(allow_none=True, validate=validate.Length(max=2000))
    steps = fields.List(fields.Dict(), missing=[])
    tags = fields.List(fields.Str(validate=validate.Length(max=50)), missing=[])

def validate_input(schema_class):
    """
    Decorator for input validation using Marshmallow schemas
    
    Args:
        schema_class: Marshmallow schema class to use for validation
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            schema = schema_class()
            
            # Get JSON data from request
            try:
                if request.is_json:
                    data = request.get_json()
                else:
                    data = request.form.to_dict()
                
                # Validate and deserialize
                validated_data = schema.load(data)
                
                # Store validated data in request context
                request.validated_data = validated_data
                
                return f(*args, **kwargs)
                
            except ValidationError as e:
                logger.warning(f"Input validation failed: {e.messages}")
                return {
                    'error': 'validation_failed',
                    'message': 'Invalid input data',
                    'details': e.messages
                }, 400
            except Exception as e:
                logger.error(f"Input validation error: {e}")
                return {
                    'error': 'validation_error',
                    'message': 'Failed to validate input'
                }, 500
                
        return decorated_function
    return decorator

def sanitize_request_data():
    """
    Sanitize all incoming request data
    Should be used as a before_request handler
    """
    if request.method in ['POST', 'PUT', 'PATCH']:
        # Sanitize form data
        if request.form:
            sanitized_form = {}
            for key, value in request.form.items():
                sanitized_key = InputSanitizer.sanitize_plain_text(key, max_length=100)
                sanitized_value = InputSanitizer.sanitize_plain_text(value, max_length=10000)
                sanitized_form[sanitized_key] = sanitized_value
            
            # Replace form data with sanitized version
            request.form = sanitized_form
        
        # Note: JSON data sanitization should be handled by validation schemas
        # to preserve data types and structure

def setup_input_sanitization(app):
    """
    Set up input sanitization for Flask app
    
    Args:
        app: Flask application instance
    """
    
    @app.before_request
    def sanitize_inputs():
        """Sanitize inputs on every request"""
        
        # Skip sanitization for static files and certain endpoints
        if request.endpoint in ['static', 'health', 'metrics']:
            return
        
        # Log potentially dangerous request patterns
        if any(pattern in request.url.lower() for pattern in 
               ['<script', 'javascript:', 'onload=', 'onerror=', 'eval(']):
            logger.warning(f"Potentially dangerous request detected: {request.url}")
            abort(400, description="Invalid request")
        
        # Check for SQL injection patterns in query parameters
        sql_patterns = ['union', 'select', 'insert', 'delete', 'drop', 'exec', '--', ';']
        for param, value in request.args.items():
            if any(pattern in value.lower() for pattern in sql_patterns):
                logger.warning(f"Potential SQL injection detected in parameter {param}: {value}")
                abort(400, description="Invalid request")
        
        # Sanitize query parameters
        sanitized_args = {}
        for key, value in request.args.items():
            sanitized_key = InputSanitizer.sanitize_plain_text(key, max_length=100)
            sanitized_value = InputSanitizer.sanitize_plain_text(value, max_length=1000)
            sanitized_args[sanitized_key] = sanitized_value
        
        # Note: Modifying request.args directly is not recommended
        # Store sanitized values in a custom attribute instead
        request.sanitized_args = sanitized_args
    
    logger.info("Input sanitization configured successfully")

# Utility functions for templates (safe alternatives to dangerouslySetInnerHTML)
def safe_render_html(content, allowed_tags=None):
    """
    Safely render HTML content in templates
    This is the safe alternative to dangerouslySetInnerHTML
    
    Args:
        content: HTML content to render
        allowed_tags: List of allowed HTML tags
        
    Returns:
        str: Safely sanitized HTML
    """
    return InputSanitizer.sanitize_html(content, allowed_tags)

def safe_render_text(content):
    """
    Safely render plain text content in templates
    
    Args:
        content: Text content to render
        
    Returns:
        str: HTML-escaped text
    """
    return InputSanitizer.sanitize_plain_text(content)

# Template context processor to make safe rendering functions available
def setup_template_helpers(app):
    """Add safe rendering functions to template context"""
    
    @app.context_processor
    def inject_safe_helpers():
        return dict(
            safe_html=safe_render_html,
            safe_text=safe_render_text
        )
