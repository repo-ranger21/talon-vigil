from celery.schedules import crontab

beat_schedule = {
    # Example: Scrape CISA alerts every day at 2AM
    "scrape_cisa_alerts_daily": {
        "task": "scraper.scrape_cisa_alerts",
        "schedule": crontab(hour=2, minute=0),
    },
    # Enrich non-enriched IOCs every hour
    "enrich_iocs_hourly": {
        "task": "enricher.enrich_pending_iocs",
        "schedule": crontab(minute=0, hour="*/1"),
    },
    # Generate summary reports nightly
    "generate_summary_reports_nightly": {
        "task": "reporter.generate_all_summary_reports",
        "schedule": crontab(hour=3, minute=0),
    },
    # Analyze playbook feedback nightly
    "analyze_playbook_feedback_nightly": {
        "task": "playbook_engine.analyze_playbook_feedback",
        "schedule": crontab(hour=4, minute=0),
    },
}