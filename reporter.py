from datetime import datetime, timedelta
from db_manager import (
    get_user_environments,
    get_user_playbooks,
    get_playbook_steps,
    IOC,
    UserEnvironment,
    Playbook,
    PlaybookStep,
    db,
)
from sqlalchemy import func

def generate_summary_report(user_id, days=30):
    """
    Generates a summary report for a user, aggregating IOC, playbook, and environment data.
    Args:
        user_id (int): The user's ID.
        days (int): The time window (in days) for IOC and playbook activity.
    Returns:
        dict: Aggregated summary data.
    """
    now = datetime.utcnow()
    since = now - timedelta(days=days)

    # Count of unique IOCs ingested in the period
    ioc_count = db.session.query(func.count(IOC.id)).filter(IOC.timestamp >= since).scalar()
    recent_iocs = (
        db.session.query(IOC)
        .filter(IOC.timestamp >= since)
        .order_by(IOC.timestamp.desc())
        .limit(10)
        .all()
    )

    # Playbooks for this user
    playbooks = (
        Playbook.query.filter_by(user_id=user_id)
        .order_by(Playbook.generated_at.desc())
        .all()
    )
    active_playbooks = [pb for pb in playbooks if pb.status in ("Active", "Draft")]
    completed_playbooks = [pb for pb in playbooks if pb.status == "Completed"]

    # Completed steps (recent)
    completed_steps = (
        db.session.query(PlaybookStep)
        .join(Playbook)
        .filter(
            Playbook.user_id == user_id,
            PlaybookStep.is_completed == True,
            PlaybookStep.completed_at >= since,
        )
        .order_by(PlaybookStep.completed_at.desc())
        .all()
    )

    # User's environment profile
    environments = get_user_environments(user_id)

    # Aggregate data
    report = {
        "ioc_summary": {
            "count": ioc_count,
            "recent_iocs": recent_iocs,
        },
        "playbook_summary": {
            "active_count": len(active_playbooks),
            "completed_count": len(completed_playbooks),
            "active_playbooks": active_playbooks[:5],
            "completed_playbooks": completed_playbooks[:5],
        },
        "completed_steps": completed_steps[:10],
        "environment_profile": environments,
        "since_date": since,
        "report_generated_at": now,
        "days": days,
    }
    return report

# Optional: Concept for text/HTML report generation for download (not fully implemented for MVP)
def render_summary_report_text(report):
    """
    Render the summary report as plain text (for download/email, etc).
    """
    lines = [
        f"ThreatCompass Summary Report ({report['days']} days)",
        f"Generated at: {report['report_generated_at'].strftime('%Y-%m-%d %H:%M')}",
        "",
        f"IOCs Ingested: {report['ioc_summary']['count']}",
        "Recent IOCs:",
    ]
    for ioc in report['ioc_summary']['recent_iocs']:
        lines.append(f" - {ioc.value} [{ioc.type}] (Source: {ioc.source}, Date: {ioc.timestamp.strftime('%Y-%m-%d')})")
    lines.append("")
    lines.append(f"Active Playbooks: {report['playbook_summary']['active_count']}")
    for pb in report['playbook_summary']['active_playbooks']:
        lines.append(f" - {pb.title} (Status: {pb.status})")
    lines.append("")
    lines.append(f"Completed Playbooks: {report['playbook_summary']['completed_count']}")
    for pb in report['playbook_summary']['completed_playbooks']:
        lines.append(f" - {pb.title} (Completed)")
    lines.append("")
    lines.append("Recent Completed Steps:")
    for step in report['completed_steps']:
        lines.append(f" - {step.instruction} (Completed at: {step.completed_at})")
    return "\n".join(lines)