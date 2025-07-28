# ...existing IOC scraping logic...
from enricher import enrich_ioc_task

def save_and_enrich_new_iocs(new_iocs):
    """
    Receives a list of dicts for new IOCs. Saves each and triggers enrichment.
    """
    from db_manager import create_ioc
    new_ioc_objs = []
    for ioc in new_iocs:
        obj = create_ioc(**ioc)
        if obj:
            new_ioc_objs.append(obj)
            # Enqueue enrichment for each new IOC
            enrich_ioc_task.delay(obj.id)
    return new_ioc_objs