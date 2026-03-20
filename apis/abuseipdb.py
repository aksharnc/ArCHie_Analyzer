"""
apis/abuseipdb.py — AbuseIPDB v2 API module.

Covers: IPv4 addresses only.
Free tier: 1,000 checks/day.
Sign up: https://www.abuseipdb.com/register
"""

import os
import requests

_BASE  = "https://api.abuseipdb.com/api/v2"
SOURCE = "AbuseIPDB"


def analyze_ip(value: str, proxies: dict) -> dict:
    key = os.getenv("ABUSEIPDB_KEY", "").strip()
    if not key:
        return {"source": SOURCE, "verdict": "skipped", "data": {}, "raw_response": None, "error": "No API key"}

    try:
        ip   = value.split("/")[0]  # strip CIDR
        resp = requests.get(
            f"{_BASE}/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            proxies=proxies,
            verify=False,
            timeout=10,
        )
        resp.raise_for_status()
        raw        = resp.json()
        d          = raw.get("data", {})
        confidence = d.get("abuseConfidenceScore", 0)

        if confidence >= 75:
            verdict = "malicious"
        elif confidence >= 10:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return {
            "source":  SOURCE,
            "verdict": verdict,
            "data": {
                "abuse_confidence": f"{confidence}%",
                "total_reports":    d.get("totalReports", 0),
                "country":          d.get("countryCode", "—"),
                "isp":              d.get("isp", "—"),
                "is_tor":           d.get("isTor", False),
                "last_reported":    d.get("lastReportedAt", "—"),
            },
            "raw_response": raw,
            "error": None,
        }
    except Exception as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
