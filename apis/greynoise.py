"""
apis/greynoise.py — GreyNoise Community API module.

Covers: IPv4 addresses only.
Free Community: 50 checks/day.
Sign up: https://viz.greynoise.io/account/signup
"""

import os
import requests

_BASE  = "https://api.greynoise.io/v3/community"
SOURCE = "GreyNoise"


def analyze_ip(value: str, proxies: dict) -> dict:
    key = os.getenv("GREYNOISE_KEY", "").strip()
    if not key:
        return {"source": SOURCE, "verdict": "skipped", "data": {}, "raw_response": None, "error": "No API key"}

    try:
        ip   = value.split("/")[0]  # strip CIDR
        resp = requests.get(
            f"{_BASE}/{ip}",
            headers={"key": key},
            proxies=proxies,
            verify=False,
            timeout=10,
        )

        # 404 = IP not seen by GreyNoise (not necessarily safe, just not observed)
        if resp.status_code == 404:
            return {
                "source":  SOURCE,
                "verdict": "clean",
                "data":    {"note": "Not observed by GreyNoise"},
                "raw_response": None,
                "error":   None,
            }

        resp.raise_for_status()
        d           = resp.json()
        noise       = d.get("noise", False)
        riot        = d.get("riot", False)     # riot = known safe (CDN, Google, etc.)
        gn_class    = d.get("classification", "unknown")  # malicious | benign | unknown
        name        = d.get("name", "—")
        last_seen   = d.get("last_seen", "—")

        if riot:
            verdict = "clean"   # RIOT = known good infrastructure
        elif gn_class == "malicious":
            verdict = "malicious"
        elif gn_class == "benign" or not noise:
            verdict = "clean"
        else:
            verdict = "suspicious"

        return {
            "source":  SOURCE,
            "verdict": verdict,
            "data": {
                "classification": gn_class,
                "known_good":     "Yes (RIOT)" if riot else "—",
                "name":           name,
            },
            "raw_response": d,
            "error": None,
        }
    except Exception as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
