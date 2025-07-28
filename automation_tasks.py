from celery import shared_task
from db_manager import db, PlaybookStep, get_security_tool_config
from datetime import datetime
import connectors.paloalto_firewall as paloalto_fw
from your_encryption_util import decrypt_api_key  # Placeholder: use proper decryption!

@shared_task
def execute_playbook_step_automation(step_id):
    step = PlaybookStep.query.get(step_id)
    if not step:
        return "[Automation] Step not found."
    if not step.security_tool_config_id or not step.action_type or not step.target_value:
        step.execution_status = "Failed"
        step.execution_log = "Incomplete step configuration for automation."
        db.session.commit()
        return step.execution_log

    config = get_security_tool_config(step.security_tool_config_id)
    if not config or not config.is_active:
        step.execution_status = "Failed"
        step.execution_log = "Security tool configuration not found or inactive."
        db.session.commit()
        return step.execution_log

    # Decrypt API key
    try:
        api_key = decrypt_api_key(config.api_key_encrypted)
    except Exception as e:
        step.execution_status = "Failed"
        step.execution_log = f"API key decryption error: {e}"
        db.session.commit()
        return step.execution_log

    # Execute action based on action_type and tool_name
    try:
        step.execution_status = "Initiated"
        db.session.commit()
        result = None
        if step.tool_used and "Palo Alto" in step.tool_used and step.action_type == "block_ip":
            result = paloalto_fw.block_ip(config.api_base_url, api_key, step.target_value)
        # Add more tool/action mappings as needed
        if result and result.get("success"):
            step.execution_status = "Success"
            step.executed_at = datetime.utcnow()
            step.execution_log = str(result.get("api_response"))
        else:
            step.execution_status = "Failed"
            step.execution_log = str(result.get("error", "Unknown error"))
    except Exception as e:
        step.execution_status = "Failed"
        step.execution_log = f"Automation error: {e}"
    db.session.commit()
    return step.execution_log