from flask import Blueprint, request, jsonify, g
from db_manager import (
    User, IOC, Playbook, PlaybookStep, UserEnvironment, db
)
from functools import wraps
from marshmallow import Schema, fields, validate, ValidationError

api_bp = Blueprint("api_bp", __name__, url_prefix="/api/v1")

# --- API Key Authentication Decorator ---
def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            return jsonify({"status": "error", "message": "Missing API key"}), 401
        user = User.query.filter_by(api_key=api_key).first()
        if not user:
            return jsonify({"status": "error", "message": "Invalid API key"}), 403
        g.current_user = user
        g.tenant_id = user.tenant_id
        return f(*args, **kwargs)
    return decorated

# --- Marshmallow Schemas ---
class IOCSchema(Schema):
    value = fields.String(required=True)
    type = fields.String(required=True, validate=validate.OneOf(["IP_ADDRESS", "DOMAIN", "MD5_HASH", "SHA1_HASH", "SHA256_HASH"]))
    source = fields.String(missing=None)
    description = fields.String(missing=None)

class EnvSchema(Schema):
    tool_type = fields.String(required=True)
    tool_name = fields.String(required=True)
    details = fields.String(missing=None)

class PlaybookStatusSchema(Schema):
    status = fields.String(required=True, validate=validate.OneOf(["Active", "Completed", "Pending"]))

class StepStatusSchema(Schema):
    is_completed = fields.Boolean(required=True)

# --- POST: Create new IOC ---
@api_bp.route("/iocs", methods=["POST"])
@api_key_required
def api_create_ioc():
    try:
        data = IOCSchema().load(request.json)
    except ValidationError as err:
        return jsonify({"status": "error", "errors": err.messages}), 400
    ioc = IOC(
        value=data["value"],
        type=data["type"],
        source=data.get("source"),
        description=data.get("description"),
        tenant_id=g.tenant_id
    )
    db.session.add(ioc)
    db.session.commit()
    return jsonify({"status": "success", "data": {"id": ioc.id}}), 201

# --- POST: Register new environment tool ---
@api_bp.route("/environment", methods=["POST"])
@api_key_required
def api_create_environment():
    try:
        data = EnvSchema().load(request.json)
    except ValidationError as err:
        return jsonify({"status": "error", "errors": err.messages}), 400
    env = UserEnvironment(
        user_id=g.current_user.id,
        tool_type=data["tool_type"],
        tool_name=data["tool_name"],
        details=data.get("details"),
        tenant_id=g.tenant_id
    )
    db.session.add(env)
    db.session.commit()
    return jsonify({"status": "success", "data": {"id": env.id}}), 201

# --- PUT/PATCH: Update playbook status ---
@api_bp.route("/playbooks/<int:playbook_id>/status", methods=["PUT", "PATCH"])
@api_key_required
def api_update_playbook_status(playbook_id):
    playbook = Playbook.query.filter_by(id=playbook_id, tenant_id=g.tenant_id).first_or_404()
    try:
        data = PlaybookStatusSchema().load(request.json)
    except ValidationError as err:
        return jsonify({"status": "error", "errors": err.messages}), 400
    playbook.status = data["status"]
    db.session.commit()
    return jsonify({"status": "success", "data": {"id": playbook.id, "status": playbook.status}})

# --- PUT/PATCH: Mark playbook step as complete ---
@api_bp.route("/playbooks/steps/<int:step_id>/status", methods=["PUT", "PATCH"])
@api_key_required
def api_update_step_status(step_id):
    step = PlaybookStep.query.filter_by(id=step_id).first_or_404()
    playbook = Playbook.query.get(step.playbook_id)
    if playbook.tenant_id != g.tenant_id:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    try:
        data = StepStatusSchema().load(request.json)
    except ValidationError as err:
        return jsonify({"status": "error", "errors": err.messages}), 400
    step.is_completed = data["is_completed"]
    db.session.commit()
    return jsonify({"status": "success", "data": {"id": step.id, "is_completed": step.is_completed}})

# --- DELETE: Remove environment tool ---
@api_bp.route("/environment/<int:tool_id>", methods=["DELETE"])
@api_key_required
def api_delete_environment(tool_id):
    env = UserEnvironment.query.filter_by(id=tool_id, tenant_id=g.tenant_id).first_or_404()
    db.session.delete(env)
    db.session.commit()
    return jsonify({"status": "success", "message": "Tool deleted"})

# --- API Documentation using Flask-RESTX (conceptual) ---
# from flask_restx import Api
# api = Api(api_bp, doc='/api/v1/docs')  # Generates /api/v1/docs as Swagger UI