"""
rate_limiter.py — Per-source API rate limit tracker for ArCHie Analyzer.

Tracks requests-per-minute per source using a sliding window.
  - Warns to console when usage reaches 80 % of the configured limit.
  - Throttles (sleeps) automatically when the limit is exhausted.

Usage:
    from rate_limiter import rate_limiter
    rate_limiter.record("VirusTotal")   # call before each API request
"""

import datetime
import json
import os
import threading
import time
from collections import deque
from pathlib import Path

from rich.console import Console

_console = Console(legacy_windows=False)

_DEFAULTS: dict[str, int] = {
    "VirusTotal":      4,
    "AbuseIPDB":       60,
    "GreyNoise":       3,
    "MalwareBazaar":   30,
    "OTX AlienVault":  60,
    "Hybrid Analysis": 5,
    "URLScan.io":      10,
    "PhishTank":       30,
    "IPInfo":          60,
    "crt.sh":          30,
    "NVD":             5,
}

_ENV_KEYS: dict[str, str] = {
    "VirusTotal":      "RATE_LIMIT_VIRUSTOTAL",
    "AbuseIPDB":       "RATE_LIMIT_ABUSEIPDB",
    "GreyNoise":       "RATE_LIMIT_GREYNOISE",
    "MalwareBazaar":   "RATE_LIMIT_MALWAREBAZAAR",
    "OTX AlienVault":  "RATE_LIMIT_OTX",
    "Hybrid Analysis": "RATE_LIMIT_HYBRID_ANALYSIS",
    "URLScan.io":      "RATE_LIMIT_URLSCAN",
    "PhishTank":       "RATE_LIMIT_PHISHTANK",
    "IPInfo":          "RATE_LIMIT_IPINFO",
    "crt.sh":          "RATE_LIMIT_CRTSH",
    "NVD":             "RATE_LIMIT_NVD",
}

_KEY_BASE_ENV: dict[str, str] = {
    "VirusTotal":      "VT_API_KEY",
    "AbuseIPDB":       "ABUSEIPDB_KEY",
    "GreyNoise":       "GREYNOISE_KEY",
    "MalwareBazaar":   "MALWAREBAZAAR_KEY",
    "OTX AlienVault":  "OTX_KEY",
    "Hybrid Analysis": "HYBRID_ANALYSIS_KEY",
    "URLScan.io":      "URLSCAN_KEY",
    "PhishTank":       "PHISHTANK_KEY",
    "IPInfo":          "IPINFO_KEY",
    "NVD":             "NVD_API_KEY",
}

_DAILY_LIMITS: dict[str, int | None] = {
    "VirusTotal":      500,
    "AbuseIPDB":       1_000,
    "GreyNoise":       50,
    "MalwareBazaar":   None,
    "OTX AlienVault":  None,
    "Hybrid Analysis": 200,
    "URLScan.io":      100,
    "PhishTank":       None,
    "IPInfo":          1_667,
    "crt.sh":          None,
    "NVD":             None,
}

_MAX_KEY_SCAN = 10


def _count_active_keys(source: str, max_keys: int = _MAX_KEY_SCAN) -> int:
    """
    Count how many non-empty API keys are configured for *source*.

    Mirrors the KeyPool scanning convention: checks BASE_ENV, BASE_ENV_2,
    BASE_ENV_3 ... and stops at the first missing/empty slot.  Returns at
    least 1 so the default rate limit is never reduced below its free-tier value.
    """
    base = _KEY_BASE_ENV.get(source)
    if not base:
        return 1
    count = 0
    if os.getenv(base, "").strip():
        count = 1
        for i in range(2, max_keys + 1):
            if os.getenv(f"{base}_{i}", "").strip():
                count += 1
            else:
                break
    return max(count, 1)


def _load_limits() -> dict[str, int | None]:
    """
    Merge defaults with any RATE_LIMIT_* overrides from the environment.

    When no explicit override is set, the default limit is automatically scaled
    by the number of active keys for that source (uses the same contiguous-scan
    convention as KeyPool: VT_API_KEY, VT_API_KEY_2, VT_API_KEY_3 ...).
    Adding more numbered keys to .env scales the rate limit up automatically.
    """
    limits: dict[str, int | None] = {}
    for source, default in _DEFAULTS.items():
        env_key = _ENV_KEYS.get(source)
        if env_key:
            raw = os.getenv(env_key, "").strip()
            if raw.isdigit():
                val = int(raw)
                limits[source] = val if val > 0 else None
                continue
        limits[source] = default * _count_active_keys(source)
    return limits


_RATE_LIMITS: dict[str, int | None] = _load_limits()

_WARN_AT = 0.80


class _SourceTracker:
    """Sliding-window (60-second) tracker for a single API source."""

    def __init__(self, limit: int):
        self._limit          = limit
        self._window: deque[float] = deque()
        self._lock           = threading.Lock()
        self._warned         = False
        self._throttle_logged = False

    def _prune(self) -> None:
        cutoff = time.monotonic() - 60.0
        while self._window and self._window[0] < cutoff:
            self._window.popleft()

    def record(self, source: str) -> None:
        while True:
            wait           = 0.0
            log_throttle   = False

            with self._lock:
                self._prune()
                current = len(self._window)

                if current >= self._limit:
                    wait = 60.0
                    if not self._throttle_logged:
                        log_throttle          = True
                        self._throttle_logged = True
                else:
                    usage = (current + 1) / self._limit
                    if usage >= _WARN_AT and not self._warned:
                        remaining = self._limit - current - 1
                        _console.print(
                            f"\n  [yellow]⚠️   [bold]{source}[/bold] approaching "
                            f"rate limit — {current + 1}/{self._limit} req/min "
                            f"({remaining} remaining this minute)[/yellow]\n"
                        )
                        self._warned = True
                    elif usage < _WARN_AT:
                        self._warned          = False
                        self._throttle_logged = False
                    self._window.append(time.monotonic())
                    return

            if log_throttle:
                _console.print(
                    f"\n  [yellow]⏳  Rate limit reached for "
                    f"[bold]{source}[/bold]. "
                    f"Cooling down for 60 s...[/yellow]\n"
                )
            if wait > 0:
                time.sleep(wait)
                with self._lock:
                    self._window.clear()
                    self._throttle_logged = False
                    self._warned          = False


class RateLimiter:
    """Thread-safe, per-source rate limiter singleton."""

    def __init__(self) -> None:
        self._trackers: dict[str, _SourceTracker] = {}
        self._lock = threading.Lock()

    def record(self, source: str) -> None:
        """
        Record one request for *source*.
        Throttles if the configured per-minute limit is reached.
        Warns at 80 % of the limit.
        No-op if the source has no configured limit.
        """
        limit = _RATE_LIMITS.get(source)
        if limit is None:
            return

        with self._lock:
            if source not in self._trackers:
                self._trackers[source] = _SourceTracker(limit)

        self._trackers[source].record(source)
        daily_tracker.record(source)


# ─── Daily Usage Tracker ──────────────────────────────────────────────────────

class DailyUsageTracker:
    """
    Persists per-source daily API call counts to output/api_usage.json.

    Resets automatically each calendar day.  Thread-safe.
    """

    _PATH = Path(__file__).parent / "output" / "api_usage.json"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data = self._load()

    @staticmethod
    def _today() -> str:
        return datetime.date.today().isoformat()

    def _load(self) -> dict:
        if self._PATH.exists():
            try:
                d = json.loads(self._PATH.read_text(encoding="utf-8"))
                if d.get("date") == self._today():
                    return d
            except (json.JSONDecodeError, KeyError, OSError):
                pass
        return {"date": self._today(), "counts": {}}

    def _save(self) -> None:
        try:
            self._PATH.parent.mkdir(parents=True, exist_ok=True)
            self._PATH.write_text(
                json.dumps(self._data, indent=2),
                encoding="utf-8",
            )
        except OSError:
            pass

    def _reset_if_new_day(self) -> None:
        """Must be called with self._lock held."""
        if self._data.get("date") != self._today():
            self._data = {"date": self._today(), "counts": {}, "exhausted": {}}

    def record(self, source: str) -> None:
        with self._lock:
            self._reset_if_new_day()
            counts = self._data.setdefault("counts", {})
            counts[source] = counts.get(source, 0) + 1
            self._save()

    def mark_exhausted(self, source: str, reason: str = "") -> None:
        """Mark *source* as having exhausted its daily quota."""
        with self._lock:
            self._reset_if_new_day()
            self._data.setdefault("exhausted", {})[source] = reason or "quota exceeded"
            self._save()

    def is_exhausted(self, source: str) -> bool:
        """Return True if *source* hit its daily quota today."""
        with self._lock:
            self._reset_if_new_day()
            return source in self._data.get("exhausted", {})

    def get_counts(self) -> dict[str, int]:
        """Return a snapshot of today's call counts, keyed by source name."""
        with self._lock:
            if self._data.get("date") != self._today():
                return {}
            return dict(self._data.get("counts", {}))

    def get_exhausted(self) -> dict[str, str]:
        """Return {source: reason} for all sources exhausted today."""
        with self._lock:
            if self._data.get("date") != self._today():
                return {}
            return dict(self._data.get("exhausted", {}))

    def clear_exhausted(self, source: str | None = None) -> None:
        """
        Clear the exhausted flag for *source*, or clear all if source is None.
        Has no effect if the source wasn't marked exhausted.
        """
        with self._lock:
            self._reset_if_new_day()
            exhausted = self._data.setdefault("exhausted", {})
            if source is None:
                exhausted.clear()
            else:
                exhausted.pop(source, None)
            self._save()


# Module-level singletons
daily_tracker = DailyUsageTracker()
rate_limiter  = RateLimiter()


# ─── API Status Helper ────────────────────────────────────────────────────────

def get_api_status() -> list[dict]:
    """
    Return a list of per-source status dicts for the --api-status display.

    Each dict contains:
      source, configured, key_count, per_min_limit, daily_limit,
      calls_today, remaining_today, exhausted
    """
    daily_counts   = daily_tracker.get_counts()
    exhausted_map  = daily_tracker.get_exhausted()
    rows = []

    for source in _DEFAULTS:
        key_base  = _KEY_BASE_ENV.get(source)

        if key_base:
            configured = bool(os.getenv(key_base, "").strip())
            key_count = _count_active_keys(source) if configured else 0
        else:
            configured = True
            key_count  = 0

        per_min   = _RATE_LIMITS.get(source)
        daily_lim = _DAILY_LIMITS.get(source)

        calls_today = daily_counts.get(source, 0)
        exhausted   = source in exhausted_map

        if exhausted:
            remaining = 0
        elif daily_lim is not None:
            remaining = max(0, daily_lim - calls_today)
        else:
            remaining = None

        rows.append({
            "source":           source,
            "configured":       configured,
            "key_count":        key_count,
            "per_min_limit":    per_min,
            "daily_limit":      daily_lim,
            "calls_today":      calls_today,
            "remaining_today":  remaining,
            "exhausted":        exhausted,
            "exhausted_reason": exhausted_map.get(source, ""),
        })

    return rows
