from flask import Blueprint, request, jsonify, g
from db_manager import (
    User, IOC, Playbook, PlaybookStep, UserEnvironment, db
)
from jwt_auth import hybrid_auth_required, jwt_required
from input_sanitization import validate_input, IOCValidationSchema, PlaybookSchema
from functools import wraps
from marshmallow import Schema, fields, validate, ValidationError
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

api_bp = Blueprint("api_bp", __name__, url_prefix="/api/v1")

# --- Rate limiting for API endpoints ---
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(key_func=get_remote_address)
except ImportError:
    # Mock limiter for development
    class MockLimiter:
        def limit(self, *args, **kwargs):
            def decorator(f):
                return f
            return decorator
    limiter = MockLimiter()

# --- Enhanced API Key Authentication Decorator ---
def api_key_or_jwt_required(scopes=None):
    """
    Enhanced authentication decorator that accepts both API keys and JWT tokens
    """
    if scopes is None:
        scopes = ['read']
    
    return hybrid_auth_required(scopes)

# --- Legacy API Key Support ---
def api_key_required(f):
    """Legacy API key authentication (deprecated, use JWT instead)"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            return jsonify({"status": "error", "message": "Missing API key"}), 401
        user = User.query.filter_by(api_key=api_key).first()
        if not user:
            return jsonify({"status": "error", "message": "Invalid API key"}), 403
        g.current_user = user
        g.current_user_id = user.id
        g.tenant_id = user.tenant_id
        return f(*args, **kwargs)
    return decorated

# --- Input Validation Schemas ---
class IOCCreateSchema(IOCValidationSchema):
    """Schema for creating IOCs with additional API-specific validation"""
    pass

class EnvironmentCreateSchema(Schema):
    """Schema for creating user environments"""
    tool_type = fields.Str(required=True, validate=validate.Length(min=1, max=64))
    tool_name = fields.Str(required=True, validate=validate.Length(min=1, max=128))
    details = fields.Str(allow_none=True, validate=validate.Length(max=1000))
    version = fields.Str(allow_none=True, validate=validate.Length(max=50))
    configuration = fields.Dict(allow_none=True)

class PlaybookStatusSchema(Schema):
    """Schema for updating playbook status"""
    status = fields.Str(required=True, validate=validate.OneOf(['pending', 'running', 'completed', 'failed']))
    message = fields.Str(allow_none=True, validate=validate.Length(max=500))
    progress = fields.Int(validate=validate.Range(min=0, max=100), allow_none=True)

class StepStatusSchema(Schema):
    """Schema for updating step status"""
    status = fields.Str(required=True, validate=validate.OneOf(['pending', 'running', 'completed', 'failed', 'skipped']))
    output = fields.Str(allow_none=True, validate=validate.Length(max=10000))
    error_message = fields.Str(allow_none=True, validate=validate.Length(max=1000))

# --- API Endpoints with Enhanced Security ---

@api_bp.route("/iocs", methods=["POST"])
@limiter.limit("20/minute")
@api_key_or_jwt_required(['write'])
@validate_input(IOCCreateSchema)
def api_create_ioc():
    """
    Create new IOC with comprehensive validation and sanitization
    """
    try:
        data = request.validated_data
        user_id = g.current_user_id
        
        # Create new IOC
        ioc = IOC(
            ioc_type=data['ioc_type'],
            value=data['value'],
            description=data.get('description'),
            source=data.get('source'),
            confidence=data.get('confidence', 50),
            user_id=user_id,
            tenant_id=g.get('tenant_id')
        )
        
        # Add tags if provided
        if data.get('tags'):
            # Sanitize tags
            from input_sanitization import InputSanitizer
            sanitized_tags = [
                InputSanitizer.sanitize_plain_text(tag, max_length=50) 
                for tag in data['tags']
            ]
            ioc.tags = sanitized_tags[:10]  # Limit to 10 tags
        
        db.session.add(ioc)
        db.session.commit()
        
        logger.info(f"IOC created: {ioc.id} by user {user_id}")
        
        return jsonify({
            "success": True,
            "ioc_id": ioc.id,
            "message": "IOC created successfully"
        }), 201
        
    except Exception as e:
        logger.error(f"IOC creation failed: {e}")
        db.session.rollback()
        return jsonify({
            "success": False,
            "error": "Failed to create IOC",
            "message": str(e)
        }), 500

@api_bp.route("/iocs", methods=["GET"])
@limiter.limit("100/minute")
@api_key_or_jwt_required(['read'])
def api_get_iocs():
    """
    Get IOCs with pagination and filtering
    """
    try:
        user_id = g.current_user_id
        tenant_id = g.get('tenant_id')
        
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)  # Max 100 per page
        ioc_type = request.args.get('type')
        source = request.args.get('source')
        
        # Build query
        query = IOC.query
        
        # Filter by tenant if multi-tenant
        if tenant_id:
            query = query.filter_by(tenant_id=tenant_id)
        else:
            query = query.filter_by(user_id=user_id)
        
        # Apply filters
        if ioc_type:
            query = query.filter_by(ioc_type=ioc_type)
        if source:
            query = query.filter_by(source=source)
        
        # Paginate results
        pagination = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        iocs = [{
            'id': ioc.id,
            'type': ioc.ioc_type,
            'value': ioc.value,
            'description': ioc.description,
            'source': ioc.source,
            'confidence': ioc.confidence,
            'tags': ioc.tags,
            'created_at': ioc.created_at.isoformat() if ioc.created_at else None
        } for ioc in pagination.items]
        
        return jsonify({
            "success": True,
            "iocs": iocs,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": pagination.total,
                "pages": pagination.pages,
                "has_next": pagination.has_next,
                "has_prev": pagination.has_prev
            }
        }), 200
        
    except Exception as e:
        logger.error(f"IOC retrieval failed: {e}")
        return jsonify({
            "success": False,
            "error": "Failed to retrieve IOCs",
            "message": str(e)
        }), 500

@api_bp.route("/environment", methods=["POST"])
@limiter.limit("10/minute")
@api_key_or_jwt_required(['write'])
@validate_input(EnvironmentCreateSchema)
def api_create_environment():
    """
    Register new environment tool with enhanced validation
    """
    try:
        data = request.validated_data
        user_id = g.current_user_id
        
        # Check if environment already exists
        existing = UserEnvironment.query.filter_by(
            user_id=user_id,
            tool_type=data['tool_type'],
            tool_name=data['tool_name']
        ).first()
        
        if existing:
            return jsonify({
                "success": False,
                "error": "Environment already exists",
                "message": f"Tool {data['tool_name']} of type {data['tool_type']} already registered"
            }), 409
        
        # Create new environment
        env = UserEnvironment(
            user_id=user_id,
            tenant_id=g.get('tenant_id'),
            tool_type=data['tool_type'],
            tool_name=data['tool_name'],
            details=data.get('details'),
            version=data.get('version'),
            configuration=data.get('configuration', {})
        )
        
        db.session.add(env)
        db.session.commit()
        
        logger.info(f"Environment created: {env.id} by user {user_id}")
        
        return jsonify({
            "success": True,
            "environment_id": env.id,
            "message": "Environment registered successfully"
        }), 201
        
    except Exception as e:
        logger.error(f"Environment creation failed: {e}")
        db.session.rollback()
        return jsonify({
            "success": False,
            "error": "Failed to create environment",
            "message": str(e)
        }), 500

@api_bp.route("/playbooks/<int:playbook_id>/status", methods=["PUT", "PATCH"])
@limiter.limit("30/minute")
@api_key_or_jwt_required(['write'])
@validate_input(PlaybookStatusSchema)
def api_update_playbook_status(playbook_id):
    """
    Update playbook status with proper authorization
    """
    try:
        data = request.validated_data
        user_id = g.current_user_id
        
        # Get playbook
        playbook = Playbook.query.get_or_404(playbook_id)
        
        # Check authorization
        if playbook.user_id != user_id and g.get('tenant_id') != playbook.tenant_id:
            return jsonify({
                "success": False,
                "error": "Unauthorized",
                "message": "You don't have permission to update this playbook"
            }), 403
        
        # Update status
        playbook.status = data['status']
        if data.get('message'):
            playbook.status_message = data['message']
        if data.get('progress') is not None:
            playbook.progress = data['progress']
        
        playbook.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        logger.info(f"Playbook {playbook_id} status updated to {data['status']} by user {user_id}")
        
        return jsonify({
            "success": True,
            "message": "Playbook status updated successfully"
        }), 200
        
    except Exception as e:
        logger.error(f"Playbook status update failed: {e}")
        db.session.rollback()
        return jsonify({
            "success": False,
            "error": "Failed to update playbook status",
            "message": str(e)
        }), 500

@api_bp.route("/playbooks/steps/<int:step_id>/status", methods=["PUT", "PATCH"])
@limiter.limit("50/minute")
@api_key_or_jwt_required(['write'])
@validate_input(StepStatusSchema)
def api_update_step_status(step_id):
    """
    Update playbook step status with proper authorization
    """
    try:
        data = request.validated_data
        user_id = g.current_user_id
        
        # Get step and playbook
        step = PlaybookStep.query.get_or_404(step_id)
        playbook = Playbook.query.get(step.playbook_id)
        
        # Check authorization
        if playbook.user_id != user_id and g.get('tenant_id') != playbook.tenant_id:
            return jsonify({
                "success": False,
                "error": "Unauthorized",
                "message": "You don't have permission to update this step"
            }), 403
        
        # Update step status
        step.status = data['status']
        if data.get('output'):
            step.output = data['output']
        if data.get('error_message'):
            step.error_message = data['error_message']
        
        step.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        logger.info(f"Step {step_id} status updated to {data['status']} by user {user_id}")
        
        return jsonify({
            "success": True,
            "message": "Step status updated successfully"
        }), 200
        
    except Exception as e:
        logger.error(f"Step status update failed: {e}")
        db.session.rollback()
        return jsonify({
            "success": False,
            "error": "Failed to update step status",
            "message": str(e)
        }), 500

# --- Health and Metrics Endpoints ---

@api_bp.route("/health", methods=["GET"])
def api_health():
    """
    API health check endpoint
    """
    try:
        # Quick database check
        db.session.execute('SELECT 1')
        
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0"
        }), 200
        
    except Exception as e:
        logger.error(f"API health check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }), 503

# --- Error Handlers for API Blueprint ---

@api_bp.errorhandler(ValidationError)
def handle_validation_error(error):
    """Handle Marshmallow validation errors"""
    logger.warning(f"API validation error: {error.messages}")
    return jsonify({
        "success": False,
        "error": "validation_failed",
        "message": "Invalid input data",
        "details": error.messages
    }), 400

@api_bp.errorhandler(404)
def handle_not_found(error):
    """Handle 404 errors in API"""
    return jsonify({
        "success": False,
        "error": "not_found",
        "message": "Resource not found"
    }), 404

@api_bp.errorhandler(429)
def handle_rate_limit(error):
    """Handle rate limit errors in API"""
    return jsonify({
        "success": False,
        "error": "rate_limit_exceeded",
        "message": "Too many requests",
        "retry_after": getattr(error, 'retry_after', 60)
    }), 429