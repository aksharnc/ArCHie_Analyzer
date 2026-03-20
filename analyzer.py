"""
analyzer.py — ArCHie Analyzer CLI Entry Point

Usage:
    python analyzer.py                             # Interactive menu
    python analyzer.py -h                          # Show all CLI flags
    python analyzer.py -i "45.33.32.156"           # Single IOC
    python analyzer.py -f iocs.txt                 # Bulk from file
    python analyzer.py --no-proxy                  # Skip Java proxy
    python analyzer.py -i "1.2.3.4" --log-raw      # Save full raw dump log
    python analyzer.py -i "1.2.3.4" --log-summary  # Save summary-only log
"""

import argparse
import sys
import os
import json
import datetime
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from dotenv import load_dotenv

# Suppress InsecureRequestWarning (we intentionally use verify=False through proxy)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

# Load .env from the project root
load_dotenv(dotenv_path=Path(__file__).parent / ".env")

import proxy_manager
from detector import detect_single, detect_bulk, IOC
from output.renderer import (
    console,
    print_banner,
    print_ioc_header,
    print_results_table,
    print_verdict_box,
    print_bulk_summary,
)

# ─── API dispatch table ────────────────────────────────────────────────────────
# Maps (ioc_type) -> list of (module_function, label) to call for that type

def _build_dispatch():
    from apis import (
        virustotal, abuseipdb, malwarebazaar, otx,
        greynoise, urlscan, ipinfo,
        crtsh, nvd, hybridanalysis, phishtank,
    )

    return {
        "md5": [
            (virustotal.analyze_hash,      "VirusTotal"),
            (malwarebazaar.analyze_hash,   "MalwareBazaar"),
            (otx.analyze_hash,             "OTX AlienVault"),
            (hybridanalysis.analyze_hash,  "Hybrid Analysis"),
        ],
        "sha1": [
            (virustotal.analyze_hash,      "VirusTotal"),
            (malwarebazaar.analyze_hash,   "MalwareBazaar"),
            (otx.analyze_hash,             "OTX AlienVault"),
            (hybridanalysis.analyze_hash,  "Hybrid Analysis"),
        ],
        "sha256": [
            (virustotal.analyze_hash,      "VirusTotal"),
            (malwarebazaar.analyze_hash,   "MalwareBazaar"),
            (otx.analyze_hash,             "OTX AlienVault"),
            (hybridanalysis.analyze_hash,  "Hybrid Analysis"),
        ],
        "ipv4": [
            (virustotal.analyze_ip,   "VirusTotal"),
            (abuseipdb.analyze_ip,    "AbuseIPDB"),
            (greynoise.analyze_ip,    "GreyNoise"),
            (otx.analyze_ip,          "OTX AlienVault"),
            (ipinfo.analyze_ip,       "IPInfo"),
        ],
        "domain": [
            (virustotal.analyze_domain,  "VirusTotal"),
            (urlscan.analyze_domain,     "URLScan.io"),
            (otx.analyze_domain,         "OTX AlienVault"),
            (crtsh.analyze_domain,       "crt.sh"),
        ],
        "url": [
            (virustotal.analyze_url,   "VirusTotal"),
            (urlscan.analyze_url,      "URLScan.io"),
            (otx.analyze_url,          "OTX AlienVault"),
            (phishtank.analyze_url,    "PhishTank"),
        ],
        "email": [
            # Extracts domain and re-dispatches through domain handlers
        ],
        "filepath": [],   # Local analysis only
        "cve":      [(nvd.analyze_cve, "NVD")],
        "unknown":  [],
    }

# ─── Run Log ────────────────────────────────────────────────────────────────────────────────

_run_log: dict = {"run_at": None, "iocs": [], "summary": {}}


def _init_log():
    _run_log["run_at"] = datetime.datetime.now().isoformat(timespec="seconds")
    _run_log["iocs"]   = []


def _log_ioc(ioc: IOC, results: list, verdict: str):
    """Append a single IOC result to the in-memory run log."""
    _run_log["iocs"].append({
        "value":         ioc.value,
        "type":          ioc.ioc_type,
        "display_label": ioc.display_label,
        "verdict":       verdict,
        "sources":       results,
    })


def _save_log(mode: str | None = None):
    """
    Write the run log to output/logs/<timestamp>.json.

    mode='raw'     : full dump — includes raw_response for every source
    mode='summary' : parsed fields only — raw_response stripped
    mode=None      : skip logging entirely
    """
    if mode is None or not _run_log["iocs"]:
        return

    counts: dict = {}
    for entry in _run_log["iocs"]:
        v = entry.get("verdict", "unknown")
        counts[v] = counts.get(v, 0) + 1
    _run_log["summary"] = counts

    log_dir = Path(__file__).parent / "output" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"run_{ts}.json"

    if mode == "summary":
        # Strip raw_response — keep only verdict + parsed data fields
        clean_iocs = []
        for entry in _run_log["iocs"]:
            clean_entry = {k: v for k, v in entry.items() if k != "sources"}
            clean_entry["sources"] = [
                {k: v for k, v in src.items() if k != "raw_response"}
                for src in entry.get("sources", [])
            ]
            clean_iocs.append(clean_entry)
        data_to_write = {
            "run_at":   _run_log["run_at"],
            "log_mode": "summary",
            "iocs":     clean_iocs,
            "summary":  _run_log["summary"],
        }
    else:  # raw
        _run_log["log_mode"] = "raw"
        data_to_write = _run_log

    log_file.write_text(
        json.dumps(data_to_write, indent=2, default=str),
        encoding="utf-8",
    )
    label = "raw dump" if mode == "raw" else "summary"
    console.print(f"  [dim]Run log ({label}) → [white]output/logs/run_{ts}.json[/white][/dim]\n")

# ─── Core analysis ────────────────────────────────────────────────────────────

def analyze_ioc(ioc: IOC, proxies: dict, dispatch: dict) -> list:
    """
    Fan out to all relevant APIs in parallel.
    Returns list of result dicts.
    """
    handlers = dispatch.get(ioc.ioc_type, [])

    # Special case: email → extract domain
    if ioc.ioc_type == "email":
        domain_ioc = detect_single(ioc.value.split("@")[1])
        return analyze_ioc(domain_ioc, proxies, dispatch)

    # Special case: filepath → local risk analysis only
    if ioc.ioc_type == "filepath":
        return [_analyze_filepath(ioc.value)]

    if not handlers:
        return [{
            "source":  "ArCHie",
            "verdict": "unknown",
            "data":    {"note": f"No handlers for type: {ioc.ioc_type}"},
            "raw_response": None,
            "error":   None,
        }]

    results = []
    with ThreadPoolExecutor(max_workers=len(handlers)) as pool:
        futures = {
            pool.submit(fn, ioc.value, proxies): label
            for fn, label in handlers
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                label = futures[future]
                results.append({
                    "source":       label,
                    "verdict":      "error",
                    "data":         {},
                    "raw_response": None,
                    "error":        str(e),
                })

    # Keep order consistent with dispatch table
    order = {label: i for i, (_, label) in enumerate(handlers)}
    results.sort(key=lambda r: order.get(r.get("source", ""), 99))
    return results


def _analyze_filepath(path: str) -> dict:
    """Local-only file path risk analysis — no API calls."""
    HIGH_RISK_EXTS = {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".hta", ".scr", ".pif", ".com", ".msi", ".lnk", ".reg",
    }
    SUSPICIOUS_PATHS = [
        "\\temp\\", "\\tmp\\", "appdata\\roaming", "appdata\\local\\temp",
        "\\windows\\temp", "\\users\\public", "%temp%", "%appdata%",
    ]

    path_lower = path.lower()
    ext        = Path(path).suffix.lower()
    risky_ext  = ext in HIGH_RISK_EXTS
    risky_path = any(p in path_lower for p in SUSPICIOUS_PATHS)

    if risky_ext and risky_path:
        verdict = "malicious"
        note    = f"High-risk extension ({ext}) in suspicious path"
    elif risky_ext:
        verdict = "suspicious"
        note    = f"High-risk extension: {ext}"
    elif risky_path:
        verdict = "suspicious"
        note    = "Suspicious path location"
    else:
        verdict = "clean"
        note    = "No obvious risk indicators"

    return {
        "source":  "Local Analysis",
        "verdict": verdict,
        "data": {
            "extension":   ext or "none",
            "path_risk":   "High-risk path" if risky_path else "Normal path",
            "assessment":  note,
        },
        "raw_response": None,
        "error": None,
    }


# ─── Single IOC flow ──────────────────────────────────────────────────────────

def run_single(raw: str, proxies: dict, dispatch: dict):
    ioc = detect_single(raw)
    print_ioc_header(ioc)

    console.print("  [dim]Querying sources...[/dim]\n")
    results = analyze_ioc(ioc, proxies, dispatch)

    print_results_table(results)
    verdict = print_verdict_box(results)
    _log_ioc(ioc, results, verdict)


# ─── Bulk IOC flow ────────────────────────────────────────────────────────────

def run_bulk(raw_input: str, proxies: dict, dispatch: dict):
    iocs = detect_bulk(raw_input)
    if not iocs:
        console.print("[yellow]No IOCs found in input.[/yellow]")
        return

    console.print(f"  [dim]Loaded {len(iocs)} IOC(s). Analyzing...[/dim]\n")
    summary_rows = []

    for i, ioc in enumerate(iocs, start=1):
        console.rule(f"[dim]IOC {i}/{len(iocs)}[/dim]", style="dim")
        print_ioc_header(ioc)
        results  = analyze_ioc(ioc, proxies, dispatch)
        print_results_table(results)
        verdict  = print_verdict_box(results)
        _log_ioc(ioc, results, verdict)

        # Build top hit for summary
        top_hit = "—"
        for r in results:
            if r.get("verdict") in ("malicious", "suspicious"):
                d = r.get("data", {})
                if "detections" in d:
                    top_hit = f"{r['source']} {d['detections']}"
                    break
                elif "abuse_confidence" in d:
                    top_hit = f"{r['source']} {d['abuse_confidence']}"
                    break

        summary_rows.append((i, ioc.value, ioc.display_label, verdict, top_hit))

    console.rule("[bold white]BULK SUMMARY[/bold white]", style="dim white")
    print_bulk_summary(summary_rows)


# ─── Interactive helpers ───────────────────────────────────────────────────────

def _ask_log_mode() -> str | None:
    """
    Prompt the user for a logging preference.
    Returns 'raw', 'summary', or None (no log).
    """
    console.print()
    console.print("  [bold white]Save a log?[/bold white]")
    console.print("  [cyan][1][/cyan]  Raw dump  [dim](all API responses + full data)[/dim]")
    console.print("  [cyan][2][/cyan]  Summary   [dim](IOC · verdict · key findings only)[/dim]")
    console.print("  [dim][0]  Skip — no log saved (default)[/dim]\n")
    try:
        choice = input("  Choice [0]: ").strip() or "0"
    except KeyboardInterrupt:
        return None
    return {"1": "raw", "2": "summary"}.get(choice, None)


def _interactive_menu(proxies: dict, dispatch: dict):
    """Show a numbered menu and loop until the user exits."""
    while True:
        console.print()
        console.print("  [bold white]What would you like to do?[/bold white]")
        console.print("  " + "─" * 42)
        console.print("  [cyan][1][/cyan]  Analyze a single IOC")
        console.print("  [cyan][2][/cyan]  Analyze IOCs from a file")
        console.print("  " + "─" * 42)
        console.print("  [dim][0]  Exit[/dim]")
        console.print()
        console.print(
            "  [dim]Tip: run [white]python analyzer.py -h[/white] "
            "to see all CLI flags.[/dim]\n"
        )

        try:
            choice = input("  Choice: ").strip()
        except KeyboardInterrupt:
            console.print("\n\n  [dim]Exiting ArCHie Analyzer. Goodbye![/dim]\n")
            sys.exit(0)

        if choice == "0":
            console.print("\n  [dim]Exiting ArCHie Analyzer. Goodbye![/dim]\n")
            sys.exit(0)

        elif choice == "1":
            try:
                raw = input("\n  Enter IOC: ").strip()
            except KeyboardInterrupt:
                continue
            if not raw:
                console.print("[yellow]  No input provided.[/yellow]")
                continue
            log_mode = _ask_log_mode()
            _init_log()
            run_single(raw, proxies, dispatch)
            _save_log(log_mode)

        elif choice == "2":
            try:
                file_path = input("\n  File path: ").strip().strip('"')
            except KeyboardInterrupt:
                continue
            path = Path(file_path)
            if not path.exists():
                console.print(f"[red]  ❌ File not found: {file_path}[/red]")
                continue
            log_mode = _ask_log_mode()
            _init_log()
            run_bulk(path.read_text(encoding="utf-8"), proxies, dispatch)
            _save_log(log_mode)

        else:
            console.print("[yellow]  Invalid choice. Enter 1, 2, or 0.[/yellow]")


# ─── Entry Point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="ArCHie Analyzer",
        description="🛡️  Threat Intel CLI — paste any IOC to analyze it.",
        epilog=(
            "Examples:\n"
            "  python analyzer.py                           Interactive menu\n"
            "  python analyzer.py -i 45.33.32.156           Single IOC\n"
            "  python analyzer.py -f iocs.txt               Bulk from file\n"
            "  python analyzer.py -i 1.2.3.4 --log-raw      Full raw dump log\n"
            "  python analyzer.py -i 1.2.3.4 --log-summary  Summary log only"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-i", "--ioc",        help="Single IOC to analyze")
    parser.add_argument("-f", "--file",       help="File containing one IOC per line")
    parser.add_argument("--no-proxy",         action="store_true",
                        help="Skip Java proxy (use direct connection)")

    log_group = parser.add_mutually_exclusive_group()
    log_group.add_argument(
        "--log-raw",
        action="store_true",
        help="Save a full raw-dump log (all API responses) after analysis",
    )
    log_group.add_argument(
        "--log-summary",
        action="store_true",
        help="Save a summary-only log (verdict + key findings, no raw responses)",
    )

    args = parser.parse_args()

    # Determine log mode from CLI flags (None = skip logging)
    if args.log_raw:
        cli_log_mode: str | None = "raw"
    elif args.log_summary:
        cli_log_mode = "summary"
    else:
        cli_log_mode = None

    _init_log()
    print_banner()

    # ── Proxy startup ──
    if args.no_proxy:
        console.print("  [yellow]⚠️  Running without proxy (--no-proxy)[/yellow]\n")
        proxies = {}
    else:
        proxy_info = proxy_manager.start(console)
        proxies    = proxy_info.get("proxies", {})
        console.print()

    dispatch = _build_dispatch()

    # ── Dispatch based on flags ──
    if args.file:
        path = Path(args.file)
        if not path.exists():
            console.print(f"[red]❌ File not found: {args.file}[/red]")
            sys.exit(1)
        run_bulk(path.read_text(encoding="utf-8"), proxies, dispatch)
        _save_log(cli_log_mode)

    elif args.ioc:
        run_single(args.ioc.strip(), proxies, dispatch)
        _save_log(cli_log_mode)

    else:
        # No flags → show interactive menu
        _interactive_menu(proxies, dispatch)


if __name__ == "__main__":
    main()
