import os
import requests
import logging
from celery import shared_task
from db_manager import get_ioc_by_id, update_ioc_enrichment

# Helper: Fetch API keys from env vars (never hardcode!)
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY")

@shared_task(rate_limit="10/m")  # Limit to 10 tasks per minute (adjust to your API plan)
def enrich_ioc_task(ioc_id):
    """
    Celery task to enrich an IOC using external APIs.
    Updates the IOC record with enrichment results.
    """
    ioc = get_ioc_by_id(ioc_id)
    if not ioc:
        logging.error(f"[enrich_ioc_task] No IOC found for id={ioc_id}")
        return

    enrichment_data = {}

    try:
        if ioc.type == "IP_ADDRESS" and ABUSEIPDB_API_KEY:
            # AbuseIPDB API
            url = "https://api.abuseipdb.com/api/v2/check"
            params = {"ipAddress": ioc.value, "maxAgeInDays": 90}
            headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
            resp = requests.get(url, params=params, headers=headers, timeout=10)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            enrichment_data["abuse_confidence"] = data.get("abuseConfidenceScore")
            enrichment_data["abuse_country"] = data.get("countryCode")
            enrichment_data["abuse_total_reports"] = data.get("totalReports")
        elif ioc.type in ("MD5_HASH", "SHA1_HASH", "SHA256_HASH") and VT_API_KEY:
            # VirusTotal API
            url = f"https://www.virustotal.com/api/v3/files/{ioc.value}"
            headers = {"x-apikey": VT_API_KEY}
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                positives = stats.get("malicious", 0)
                total = sum(stats.values())
                enrichment_data["vt_score"] = f"{positives}/{total}" if total else None
                enrichment_data["vt_permalink"] = data.get("links", {}).get("self")
            else:
                logging.warning(f"[enrich_ioc_task] VT lookup for {ioc.value} returned {resp.status_code}")
        # Add more enrichment sources for DOMAIN, URL, etc. as needed.
    except Exception as e:
        logging.error(f"[enrich_ioc_task] Error enriching IOC {ioc.value}: {e}")

    # Save enrichment data to DB if we got anything new
    if enrichment_data:
        update_ioc_enrichment(ioc_id, enrichment_data)
    else:
        logging.info(f"[enrich_ioc_task] No enrichment data available for IOC {ioc.value}")

    return enrichment_data