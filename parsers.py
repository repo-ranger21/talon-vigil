import re
from bs4 import BeautifulSoup

IOC_TYPE_REGEXES = {
    "IP_ADDRESS": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "DOMAIN": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    "MD5_HASH": r"\b[a-fA-F0-9]{32}\b",
    "SHA1_HASH": r"\b[a-fA-F0-9]{40}\b",
    "SHA256_HASH": r"\b[a-fA-F0-9]{64}\b",
    "URL": r"https?://[^\s\"'>]+",
}

def parse_cisa_html(html_content):
    """
    Parses the CISA advisories HTML for IOCs (IPs, domains, hashes, URLs).
    Returns a list of dicts ready for IOC model insertion.
    """
    if not html_content:
        return []

    soup = BeautifulSoup(html_content, "html.parser")
    ioc_set = set()
    iocs = []

    # Heuristic: look for sections/paragraphs/tables likely to contain IOCs
    potential_text_blocks = soup.find_all(["p", "li", "td", "pre", "code"])
    for block in potential_text_blocks:
        text = block.get_text(" ", strip=True)
        for ioc_type, pattern in IOC_TYPE_REGEXES.items():
            for match in re.findall(pattern, text):
                key = (match, ioc_type)
                if key not in ioc_set:
                    ioc_set.add(key)
                    iocs.append({
                        "value": match,
                        "type": ioc_type,
                        "source": "CISA",
                        "description": f"Extracted from CISA advisory: {text[:120]}..."  # Sample context
                    })

    return iocs

# NOTE: This is a simple parser for demo. For production, consider more context-aware extraction.