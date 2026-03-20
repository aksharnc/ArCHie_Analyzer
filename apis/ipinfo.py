"""
apis/ipinfo.py — IPInfo.io geolocation module.

Covers: IPv4 addresses.
No API key needed for basic geo (org, city, country).
Optional key for higher rate limits: https://ipinfo.io/signup
"""

import os
import requests

SOURCE = "IPInfo"


def analyze_ip(value: str, proxies: dict) -> dict:
    try:
        ip    = value.split("/")[0]   # strip CIDR
        key   = os.getenv("IPINFO_KEY", "").strip()
        token = f"?token={key}" if key else ""
        resp  = requests.get(
            f"https://ipinfo.io/{ip}/json{token}",
            proxies=proxies,
            verify=False,
            timeout=8,
        )
        resp.raise_for_status()
        d    = resp.json()
        org  = d.get("org", "—")

        # IPInfo always returns geo — verdict is always INFO (not a threat feed)
        return {
            "source":  SOURCE,
            "verdict": "info",
            "data": {
                "org":      org,
                "city":     d.get("city", "—"),
                "region":   d.get("region", "—"),
                "country":  d.get("country", "—"),
                "timezone": d.get("timezone", "—"),
            },
            "raw_response": d,
            "error": None,
        }
    except Exception as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
