"""
analyzer.py — ArCHie Analyzer CLI Entry Point

Usage:
    python analyzer.py                              # Interactive menu
    python analyzer.py -h                           # Show all CLI flags
    python analyzer.py -i "45.33.32.156"            # Single IOC  (quiet mode)
    python analyzer.py -i "1.2.3.4" --verbose       # Verbose / real-time output
    python analyzer.py -f iocs.txt                  # Bulk from file
    python analyzer.py -f iocs.txt --workers 10     # Custom thread pool size
    python analyzer.py --no-proxy                   # Skip Java proxy
    python analyzer.py -i "1.2.3.4" --log-raw       # Save full raw dump log
    python analyzer.py -i "1.2.3.4" --no-cache      # Bypass result cache
    python analyzer.py -f iocs.txt --output csv     # Export results to CSV
    python analyzer.py -f iocs.txt --output json    # Export results to JSON
"""

import argparse
import csv
import sys
import os
import json
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from dotenv import load_dotenv

if sys.platform == "win32":
    import io
    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "buffer"):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv(dotenv_path=Path(__file__).parent / ".env")

import proxy_manager
import cache as ioc_cache
from rate_limiter import rate_limiter, get_api_status, daily_tracker
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
        "email": [],
        "filepath": [],
        "cve":      [(nvd.analyze_cve, "NVD")],
        "unknown":  [],
    }

# ─── Source filter ──────────────────────────────────────────────────────────

_ALL_SOURCES: list[str] = [
    "VirusTotal", "AbuseIPDB", "GreyNoise", "MalwareBazaar",
    "OTX AlienVault", "Hybrid Analysis", "URLScan.io", "PhishTank",
    "IPInfo", "crt.sh", "NVD",
]


def _filter_dispatch(dispatch: dict, sources: list[str]) -> dict:
    """
    Return a copy of *dispatch* that only contains handlers whose label
    matches one of the requested *sources* (case-insensitive).
    If *sources* is empty the original dispatch is returned unchanged.
    """
    if not sources:
        return dispatch
    needle = {s.strip().lower() for s in sources}
    return {
        ioc_type: [(fn, lbl) for fn, lbl in handlers if lbl.lower() in needle]
        for ioc_type, handlers in dispatch.items()
    }


# ─── API Status Display ───────────────────────────────────────────────────────

def _print_api_status() -> None:
    """Print a table showing per-source API status, limits, and usage today."""
    from rich.table import Table
    from rich import box

    rows = get_api_status()
    today = datetime.date.today().strftime("%A, %d %b %Y")

    console.print()
    console.rule(f"[bold white] API STATUS — {today} [/bold white]", style="color(54)")
    console.print()

    tbl = Table(
        box=box.ROUNDED,
        border_style="color(54)",
        header_style="bold white",
        show_lines=True,
        padding=(0, 1),
    )
    tbl.add_column("Source",         style="white",    min_width=16)
    tbl.add_column("Status",         justify="center", min_width=11)
    tbl.add_column("Daily Limit",    justify="right",  min_width=11)
    tbl.add_column("ArCHie Calls",   justify="right",  min_width=12)
    tbl.add_column("Est. Remaining", justify="right",  min_width=14)

    for r in rows:
        configured  = r["configured"]
        calls_today = r["calls_today"]
        daily_lim   = r["daily_limit"]
        remaining   = r["remaining_today"]
        exhausted   = r["exhausted"]

        if not configured:
            status_str = "[dim]NO KEY[/dim]"
        elif exhausted:
            status_str = "[bold red]EXHAUSTED[/bold red]"
        else:
            status_str = "[green]OK[/green]"

        daily_str = f"{daily_lim:,}" if daily_lim is not None else "[dim]—[/dim]"

        if exhausted:
            used_str = f"[bold red]{calls_today:,}[/bold red]"
        elif daily_lim and calls_today >= daily_lim * 0.80:
            used_str = f"[yellow]{calls_today:,}[/yellow]"
        else:
            used_str = f"{calls_today:,}" if calls_today > 0 else "[dim]0[/dim]"

        if remaining is None:
            rem_str = "[dim]—[/dim]"
        elif remaining == 0:
            rem_str = "[bold red]0[/bold red]"
        elif daily_lim and remaining <= daily_lim * 0.20:
            rem_str = f"[yellow]{remaining:,}[/yellow]"
        else:
            rem_str = f"[green]{remaining:,}[/green]"

        tbl.add_row(
            r["source"],
            status_str,
            daily_str,
            used_str,
            rem_str,
        )

    console.print(tbl)

    console.print(
        "  [dim]"
        "Status: [green]OK[/green] = key set  "
        "[bold red]EXHAUSTED[/bold red] = daily quota hit  "
        "[dim]NO KEY[/dim] = key missing in .env[/dim]"
    )
    console.print(
        "  [dim]ArCHie Calls = calls made through this tool only "
        "(external usage is not counted)[/dim]"
    )
    console.print(
        "  [dim]Tip: run [white]python analyzer.py --mark-exhausted \"VirusTotal\"[/white] "
        "to manually flag a source as exhausted until midnight.[/dim]"
    )
    console.print()


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


def _handle_interrupt(log_mode: str | None, output_fmt: str | None) -> None:
    """
    Clean Ctrl+C handler — suppress the traceback, prompt the user for
    what intermediate output to save, then exit.
    """
    console.print("\n\n  [yellow]⚠  Scan interrupted (Ctrl+C).[/yellow]")

    completed = len(_run_log["iocs"])
    if not completed:
        console.print("  [dim]No results collected yet. Exiting.[/dim]\n")
        sys.exit(0)

    console.print(f"  [dim]{completed} IOC(s) completed before interrupt.[/dim]\n")

    console.print("  [bold white]Save partial results?[/bold white]")
    console.print("  [cyan][1][/cyan]  Summary log   [dim](verdict + key findings)[/dim]")
    console.print("  [cyan][2][/cyan]  Raw dump log   [dim](full API responses)[/dim]")
    console.print("  [cyan][3][/cyan]  Export as CSV")
    console.print("  [cyan][4][/cyan]  Export as JSON")
    console.print("  [cyan][5][/cyan]  All of the above")
    console.print("  [dim][0]  Skip — exit without saving[/dim]\n")

    try:
        choice = input("  Choice [1]: ").strip() or "1"
    except (KeyboardInterrupt, EOFError):
        console.print("\n  [dim]Exiting ArCHie Analyzer.[/dim]\n")
        sys.exit(0)

    choices = set(choice.replace(",", " ").split())
    if "5" in choices:
        choices = {"1", "2", "3", "4"}

    if "0" in choices:
        console.print("  [dim]No output saved. Exiting.[/dim]\n")
        sys.exit(0)

    if "1" in choices:
        _save_log("summary")
    if "2" in choices:
        _save_log("raw")
    if "3" in choices:
        _export_results("csv")
    if "4" in choices:
        _export_results("json")

    if not choices & {"1", "2", "3", "4"}:
        _save_log("summary")
        console.print("  [dim]Defaulted to summary log.[/dim]")

    console.print("  [dim]Exiting ArCHie Analyzer.[/dim]\n")
    sys.exit(0)


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

    log_dir = Path(__file__).parent / "output" / "logs" / "json"
    log_dir.mkdir(parents=True, exist_ok=True)
    ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"run_{ts}.json"

    if mode == "summary":
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
    else:
        _run_log["log_mode"] = "raw"
        data_to_write = _run_log

    log_file.write_text(
        json.dumps(data_to_write, indent=2, default=str),
        encoding="utf-8",
    )
    label = "raw dump" if mode == "raw" else "summary"
    console.print(f"  [dim]Run log ({label}) -> [white]output/logs/json/run_{ts}.json[/white][/dim]\n")

# ─── Core analysis ────────────────────────────────────────────────────────────

def analyze_ioc(ioc: IOC, proxies: dict, dispatch: dict, workers: int = 5) -> list:
    """
    Fan out to all relevant APIs in parallel.
    Returns list of result dicts.
    Integrates cache (skip hit sources) and rate limiter (throttle/warn).
    """
    handlers = dispatch.get(ioc.ioc_type, [])

    if ioc.ioc_type == "email":
        domain_ioc = detect_single(ioc.value.split("@")[1])
        return analyze_ioc(domain_ioc, proxies, dispatch, workers)
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

    results: list = []
    futures_map: dict = {}

    with ThreadPoolExecutor(max_workers=min(workers, len(handlers))) as pool:
        for fn, label in handlers:
            cached = ioc_cache.get(label, ioc.value)
            if cached is not None:
                results.append(cached)
                continue

            def _call(fn=fn, label=label):
                rate_limiter.record(label)
                return fn(ioc.value, proxies)

            futures_map[pool.submit(_call)] = label

        for future in as_completed(futures_map):
            label = futures_map[future]
            try:
                result = future.result()
                if result.get("verdict") not in ("error", "skipped"):
                    ioc_cache.set(label, ioc.value, result)
                results.append(result)
            except Exception as e:
                results.append({
                    "source":       label,
                    "verdict":      "error",
                    "data":         {},
                    "raw_response": None,
                    "error":        str(e),
                })

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
        note = f"High-risk extension ({ext}) in suspicious path"
    elif risky_ext:
        note = f"High-risk extension: {ext}"
    elif risky_path:
        note = "Suspicious path location"
    else:
        note = "No obvious risk indicators"

    return {
        "source":  "Local Analysis",
        "verdict": "info",
        "data": {
            "extension":   ext or "none",
            "path_risk":   "High-risk path" if risky_path else "Normal path",
            "assessment":  note,
        },
        "raw_response": None,
        "error": None,
    }


# ─── Single IOC flow ──────────────────────────────────────────────────────────

def run_single(raw: str, proxies: dict, dispatch: dict,
               verbose: bool = False, workers: int = 5) -> str:
    """
    Analyze a single IOC.
      verbose=True  : shows IOC header, 'Querying...' message, table, verdict box
      verbose=False : spinner while querying, then table + verdict box (quiet mode)
    Returns the overall verdict string.
    """
    from rich.progress import Progress, SpinnerColumn, TextColumn

    ioc = detect_single(raw)

    if verbose:
        print_ioc_header(ioc)
        console.print(_cache_status_msg(ioc, dispatch))
        results = analyze_ioc(ioc, proxies, dispatch, workers)
    else:
        with Progress(
            SpinnerColumn(style="color(54)"),
            TextColumn("[dim]{task.description}[/dim]"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task(
                f"Querying {ioc.display_label}: {ioc.value[:60]}...",
                total=None,
            )
            results = analyze_ioc(ioc, proxies, dispatch, workers)
        print_ioc_header(ioc)

    print_results_table(results, ioc_type=ioc.ioc_type)
    verdict = print_verdict_box(results)
    _log_ioc(ioc, results, verdict)
    return verdict


# ─── Bulk IOC flow ────────────────────────────────────────────────────────────

def run_bulk(raw_input: str, proxies: dict, dispatch: dict,
             verbose: bool = False, workers: int = 5):
    """
    Analyze multiple IOCs from text input.
      verbose=False (default/quiet): progress bar → bulk summary table only
      verbose=True                 : per-IOC header + tables → progress counter → bulk summary
    """
    from rich.progress import (
        Progress, BarColumn, MofNCompleteColumn,
        TextColumn, TimeElapsedColumn,
    )

    iocs = detect_bulk(raw_input)
    if not iocs:
        console.print("[yellow]No IOCs found in input.[/yellow]")
        return

    console.print(f"  [dim]Loaded {len(iocs)} IOC(s). Analyzing...[/dim]\n")
    summary_rows: list = []

    if verbose:
        with Progress(
            TextColumn("[dim]  [{task.completed}/{task.total}][/dim]"),
            BarColumn(bar_width=30, style="color(54)"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("Analyzing", total=len(iocs))

            for i, ioc in enumerate(iocs, start=1):
                progress.update(task, description=f"  [{i}/{len(iocs)}] {ioc.value[:35]}")
                console.rule(f"[dim]IOC {i}/{len(iocs)}[/dim]", style="dim")
                print_ioc_header(ioc)
                console.print(_cache_status_msg(ioc, dispatch))
                results = analyze_ioc(ioc, proxies, dispatch, workers)
                print_results_table(results, ioc_type=ioc.ioc_type)
                verdict = print_verdict_box(results)
                _log_ioc(ioc, results, verdict)
                summary_rows.append(_make_summary_row(i, ioc, results, verdict))
                progress.advance(task)

    else:
        with Progress(
            TextColumn("  [dim]{task.description}[/dim]"),
            BarColumn(bar_width=40, style="color(54)"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("Analyzing IOCs", total=len(iocs))

            for i, ioc in enumerate(iocs, start=1):
                progress.update(task, description=f"Analyzing: {ioc.value[:40]}")
                results = analyze_ioc(ioc, proxies, dispatch, workers)
                verdict = _compute_verdict_str(results)
                _log_ioc(ioc, results, verdict)
                summary_rows.append(_make_summary_row(i, ioc, results, verdict))
                progress.advance(task)

        console.print()

    console.rule("[bold white]BULK SUMMARY[/bold white]", style="dim white")
    print_bulk_summary(summary_rows)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _cache_status_msg(ioc, dispatch: dict) -> str:
    """
    Pre-check cache for every handler of this IOC type.
    Returns a coloured status line shown in verbose mode before analysis starts.
    """
    check_value = ioc.value
    check_type  = ioc.ioc_type
    if check_type == "email" and "@" in ioc.value:
        check_value = ioc.value.split("@")[1]
        check_type  = "domain"

    handlers = dispatch.get(check_type, [])
    if not handlers:
        return "  [dim]No external sources for this IOC type.[/dim]\n"

    hits  = sum(1 for _, lbl in handlers if ioc_cache.get(lbl, check_value) is not None)
    total = len(handlers)

    if hits == total:
        return f"  [dim]>> All {total} sources loaded from cache.[/dim]\n"
    elif hits > 0:
        return (
            f"  [dim]>> {hits}/{total} from cache | "
            f"querying {total - hits} source(s)...[/dim]\n"
        )
    return "  [dim]Querying sources...[/dim]\n"


def _compute_verdict_str(results: list) -> str:
    """Return the overall verdict string for a results list (without printing)."""
    from output.renderer import _compute_verdict
    return _compute_verdict(results)["verdict"]


def _make_summary_row(idx: int, ioc, results: list, verdict: str) -> tuple:
    """Build the (idx, value, type_label, verdict, top_hit) tuple for bulk summary."""
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
    return (idx, ioc.value, ioc.display_label, verdict, top_hit)


# ─── CSV / JSON export ────────────────────────────────────────────────────────

def _export_results(output_format: str) -> None:
    """
    Export the in-memory run log to output/results.csv or output/results.json.
    Called after all IOCs have been processed.
    """
    if not _run_log["iocs"]:
        return

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    if output_format == "json":
        out_dir = Path(__file__).parent / "output" / "logs" / "json"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"results_{ts}.json"
        out_path.write_text(
            json.dumps(_run_log, indent=2, default=str),
            encoding="utf-8",
        )
        console.print(f"  [dim]JSON export -> [white]output/logs/json/results_{ts}.json[/white][/dim]\n")

    elif output_format == "csv":
        out_dir = Path(__file__).parent / "output" / "logs" / "csv"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"results_{ts}.csv"
        with out_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["IOC", "Type", "Overall Verdict", "Source", "Verdict", "Key Finding"])
            for entry in _run_log["iocs"]:
                for src in entry.get("sources", []):
                    data    = src.get("data", {})
                    finding = "  |  ".join(
                        str(v) for v in data.values()
                        if v is not None and str(v) != "—"
                    )[:120]
                    writer.writerow([
                        entry["value"],
                        entry["type"],
                        entry["verdict"],
                        src.get("source", "?"),
                        src.get("verdict", "?"),
                        finding,
                    ])
        console.print(f"  [dim]CSV export -> [white]output/logs/csv/results_{ts}.csv[/white][/dim]\n")


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


def _interactive_menu(proxies: dict, dispatch: dict, verbose: bool, workers: int,
                      active_sources: list[str] | None = None):
    """Show a numbered menu and loop until the user exits."""
    if active_sources:
        console.print(
            f"  [dim]Source filter active: "
            + ", ".join(f"[white]{s}[/white]" for s in active_sources)
            + "[/dim]\n"
        )
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
            if verbose:
                log_mode = _ask_log_mode()
            else:
                log_mode = "summary"
            _init_log()
            run_single(raw, proxies, dispatch, verbose=verbose, workers=workers)
            _save_log(log_mode)

        elif choice == "2":
            try:
                file_path = input("\n  File path: ").strip().strip('"')
            except KeyboardInterrupt:
                continue
            path = Path(file_path)
            if not path.exists():
                console.print(f"[red]  \u274c File not found: {file_path}[/red]")
                continue
            if verbose:
                log_mode = _ask_log_mode()
            else:
                log_mode = "summary"

            _init_log()
            run_bulk(path.read_text(encoding="utf-8"), proxies, dispatch,
                     verbose=verbose, workers=workers)
            _save_log(log_mode)

        else:
            console.print("[yellow]  Invalid choice. Enter 1, 2, or 0.[/yellow]")


# ─── Entry Point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="archie",
        description="ArCHie Analyzer -- Threat Intel CLI. Paste any IOC to analyze it.",
        epilog=(
            "Examples:\n"
            "  archie                          Interactive menu\n"
            "  archie -i 1.2.3.4              Analyze single IOC\n"
            "  archie -i 1.2.3.4 -v           Verbose output\n"
            "  archie -f iocs.txt             Bulk from file\n"
            "  archie -f iocs.txt -o csv      Export to CSV\n"
            "  archie --api-status            API usage dashboard\n"
            "  archie --list-sources          Show all source names"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-i", "--ioc",      help="Single IOC to analyze")
    parser.add_argument("-f", "--file",     help="File containing one IOC per line")
    parser.add_argument(
        "-s", "--sources",
        metavar="SOURCE,...",
        help=(
            'Comma-separated list of sources to query, e.g. "VirusTotal,AbuseIPDB". '
            "All other sources are skipped. Use --list-sources to see valid names."
        ),
    )
    parser.add_argument(
        "--list-sources",
        action="store_true",
        help="Print all available source names and exit.",
    )
    parser.add_argument(
        "--api-status",
        action="store_true",
        help="Show API key configuration, rate limits, and today's call counts, then exit.",
    )
    parser.add_argument(
        "--mark-exhausted",
        metavar="SOURCE",
        help=(
            'Manually mark a source as EXHAUSTED until midnight, e.g. "VirusTotal". '
            "Use when you know the daily quota is gone from external usage. "
            "Run --list-sources to see valid names."
        ),
    )
    parser.add_argument(
        "--clear-exhausted",
        metavar="SOURCE",
        help='Clear the EXHAUSTED flag for a source, e.g. "VirusTotal" (or "all" to clear all).',
    )
    parser.add_argument("-np", "--no-proxy",  action="store_true",
                        help="Skip Java proxy (use direct connection)")
    parser.add_argument("-v", "--verbose",  action="store_true",
                        help="Show real-time API output per source (default: quiet mode)")
    parser.add_argument("-nc", "--no-cache", action="store_true",
                        help="Bypass result cache — always query APIs fresh")
    parser.add_argument("-w", "--workers",  type=int, default=5, metavar="N",
                        help="Thread pool size for parallel API calls (default: 5, max: 20)")
    parser.add_argument("-o", "--output",   choices=["csv", "json"],
                        help="Export results to output/csv/ (csv) or output/logs/ (json)")

    log_group = parser.add_mutually_exclusive_group()
    log_group.add_argument(
        "-lr", "--log-raw",
        action="store_true",
        help="Save a full raw-dump log (all API responses) after analysis",
    )
    log_group.add_argument(
        "-ls", "--log-summary",
        action="store_true",
        help="Save a summary-only log (verdict + key findings, no raw responses)",
    )

    args = parser.parse_args()

    if args.list_sources:
        print_banner()
        console.print("  [bold white]Available source names[/bold white] (use with -s):\n")
        for name in _ALL_SOURCES:
            console.print(f"    [cyan]•[/cyan]  {name}")
        console.print()
        sys.exit(0)

    if args.api_status:
        print_banner()
        _print_api_status()
        sys.exit(0)

    if args.mark_exhausted:
        source = args.mark_exhausted.strip()
        match = next((s for s in _ALL_SOURCES if s.lower() == source.lower()), None)
        if not match:
            print_banner()
            console.print(
                f"  [red]Unknown source: {source!r}. "
                f"Run --list-sources to see valid names.[/red]"
            )
            sys.exit(1)
        daily_tracker.mark_exhausted(match, "manual")
        console.print(
            f"  [green]✓[/green]  [bold white]{match}[/bold white] marked as "
            f"[bold red]EXHAUSTED[/bold red] until midnight."
        )
        sys.exit(0)

    if args.clear_exhausted:
        target = args.clear_exhausted.strip()
        if target.lower() == "all":
            daily_tracker.clear_exhausted()
            console.print("  [green]✓[/green]  Cleared EXHAUSTED flag for all sources.")
        else:
            match = next((s for s in _ALL_SOURCES if s.lower() == target.lower()), None)
            if not match:
                print_banner()
                console.print(
                    f"  [red]Unknown source: {target!r}. "
                    f"Run --list-sources to see valid names.[/red]"
                )
                sys.exit(1)
            daily_tracker.clear_exhausted(match)
            console.print(
                f"  [green]✓[/green]  Cleared EXHAUSTED flag for "
                f"[bold white]{match}[/bold white]."
            )
        sys.exit(0)

    if args.no_cache:
        ioc_cache.enable(False)

    if args.log_raw:
        cli_log_mode: str | None = "raw"
    elif args.log_summary:
        cli_log_mode = "summary"
    elif not args.verbose:
        cli_log_mode = "summary"
    else:
        cli_log_mode = None

    _init_log()
    print_banner()

    if args.no_proxy:
        console.print("  [yellow][!] Running without proxy (--no-proxy)[/yellow]\n")
        proxies = {}
    else:
        proxy_info = proxy_manager.start(console)
        proxies    = proxy_info.get("proxies", {})
        console.print()

    dispatch = _build_dispatch()
    workers  = max(1, min(args.workers, 20))

    active_sources: list[str] = []
    if args.sources:
        active_sources = [s.strip() for s in args.sources.split(",") if s.strip()]
        known_lower = {n.lower() for n in _ALL_SOURCES}
        bad = [s for s in active_sources if s.lower() not in known_lower]
        if bad:
            console.print(
                f"  [yellow]⚠️  Unknown source(s): {', '.join(bad)}. "
                f"Run --list-sources to see valid names.[/yellow]\n"
            )
        dispatch = _filter_dispatch(dispatch, active_sources)
        console.print(
            "  [dim]Source filter: "
            + ", ".join(f"[white]{s}[/white]" for s in active_sources)
            + "[/dim]\n"
        )

    try:
        if args.file:
            path = Path(args.file)
            if not path.exists():
                console.print(f"[red]❌ File not found: {args.file}[/red]")
                sys.exit(1)
            run_bulk(path.read_text(encoding="utf-8"), proxies, dispatch,
                     verbose=args.verbose, workers=workers)
            _save_log(cli_log_mode)
            if args.output:
                _export_results(args.output)

        elif args.ioc:
            run_single(args.ioc.strip(), proxies, dispatch,
                       verbose=args.verbose, workers=workers)
            _save_log(cli_log_mode)
            if args.output:
                _export_results(args.output)

        else:
            _interactive_menu(proxies, dispatch,
                              verbose=args.verbose, workers=workers,
                              active_sources=active_sources or None)

    except KeyboardInterrupt:
        _handle_interrupt(cli_log_mode, args.output)


if __name__ == "__main__":
    main()
