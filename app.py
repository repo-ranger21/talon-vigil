from flask import request, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user
from db_manager import PlaybookStep, Playbook, db
from rbac import role_required
from automation_tasks import execute_playbook_step_automation

@app.route("/playbooks/steps/<int:step_id>/execute_automation", methods=["POST"])
@login_required
@role_required('admin')  # Or adjust as needed
def execute_step_automation(step_id):
    step = PlaybookStep.query.get_or_404(step_id)
    playbook = Playbook.query.get(step.playbook_id)
    # Ensure user has permission (is admin or owns playbook/tenant)
    if playbook.user_id != current_user.id and not current_user.is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    # Require explicit consent (e.g., ?confirm=true)
    if not (request.args.get("confirm") == "true" or request.json.get("confirm") is True):
        return jsonify({"success": False, "message": "Consent required"}), 400
    # Enqueue the Celery task
    execute_playbook_step_automation.delay(step_id)
    step.execution_status = "Pending"
    db.session.commit()
    return jsonify({"success": True, "message": "Automation initiated. Refresh to see status."})