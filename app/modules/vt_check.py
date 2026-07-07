"""
VirusTotal integration for extracted files.

Requires a VT_API_KEY environment variable — get a free key at
https://www.virustotal.com/gui/join-us
"""
from datetime import datetime, timezone

import requests

VT_LOOKUP_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
TIMEOUT_SECONDS = 15


class VTNotConfigured(Exception):
    pass


class VTLookupError(Exception):
    pass


def check_hash(sha256: str, api_key: str) -> dict:
    if not api_key:
        raise VTNotConfigured("No VT_API_KEY configured.")

    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(
            VT_LOOKUP_URL.format(sha256=sha256),
            headers=headers, timeout=TIMEOUT_SECONDS
        )
    except requests.RequestException as exc:
        raise VTLookupError(str(exc)) from exc

    if resp.status_code == 404:
        return {"found": False, "malicious_count": None,
                "total_engines": None, "permalink": None}

    if resp.status_code != 200:
        raise VTLookupError(f"VirusTotal returned HTTP {resp.status_code}: {resp.text[:200]}")

    data = resp.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0

    return {
        "found": True,
        "malicious_count": malicious + suspicious,
        "total_engines": total,
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
    }


def check_extracted_file(extracted_file, api_key: str):
    result = check_hash(extracted_file.sha256, api_key)

    extracted_file.vt_checked = True
    extracted_file.vt_checked_at = datetime.now(timezone.utc).replace(tzinfo=None)
    extracted_file.vt_malicious_count = result["malicious_count"]
    extracted_file.vt_total_engines = result["total_engines"]
    extracted_file.vt_report_url = result["permalink"]

    return extracted_file