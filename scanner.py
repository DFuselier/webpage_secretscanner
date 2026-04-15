#!/usr/bin/env python3
"""
js-secret-scanner
-----------------
Crawls a target URL, downloads JS/JSON/config files,
beautifies minified code, and scans for hardcoded secrets
using regex patterns and Shannon entropy analysis.

For authorized security research and bug bounty use only.
"""

import argparse
import hashlib
import json
import math
import os
import re
import sys
import time
from urllib.parse import urljoin, urlparse

import jsbeautifier
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from rich.console import Console
from rich.table import Table

init(autoreset=True)
console = Console()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 10
DEFAULT_DELAY   = 0.5   # seconds between requests (be polite)
ENTROPY_THRESHOLD = 4.2  # Shannon entropy threshold for flagging strings

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"
}

# File extensions to download and scan
TARGET_EXTENSIONS = (
    ".js", ".json", ".map", ".env", ".config",
    ".conf", ".xml", ".yaml", ".yml", ".ts"
)

# Filenames to always attempt (path traversal/common locations)
WORDLIST_PATHS = [
    "/.env",
    "/.env.production",
    "/.env.local",
    "/config.json",
    "/settings.json",
    "/appsettings.json",
    "/web.config",
    "/swagger.json",
    "/openapi.json",
    "/api-docs.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/wp-json/wp/v2/users",
    "/sitemap.xml",
    "/robots.txt",
]

# ---------------------------------------------------------------------------
# Secret patterns  (name, compiled regex)
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    # Generic credential assignments
    ("Generic Password",        re.compile(r'(?i)(password|passwd|pass|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']')),
    ("Generic Secret",          re.compile(r'(?i)(secret|api_secret|client_secret)\s*[:=]\s*["\']([^"\']{8,})["\']')),
    ("Generic API Key",         re.compile(r'(?i)(api_key|apikey|api-key)\s*[:=]\s*["\']([^"\']{8,})["\']')),
    ("Generic Token",           re.compile(r'(?i)(token|auth_token|access_token|bearer)\s*[:=]\s*["\']([^"\']{8,})["\']')),

    # Service-specific
    ("AWS Access Key",          re.compile(r'AKIA[0-9A-Z]{16}')),
    ("AWS Secret Key",          re.compile(r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']')),
    ("Stripe Live Key",         re.compile(r'sk_live_[0-9a-zA-Z]{24,}')),
    ("Stripe Test Key",         re.compile(r'sk_test_[0-9a-zA-Z]{24,}')),
    ("Stripe Publishable Key",  re.compile(r'pk_live_[0-9a-zA-Z]{24,}')),
    ("SendGrid API Key",        re.compile(r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}')),
    ("Mailgun API Key",         re.compile(r'key-[0-9a-zA-Z]{32}')),
    ("Twilio Account SID",      re.compile(r'AC[a-zA-Z0-9]{32}')),
    ("Twilio Auth Token",       re.compile(r'(?i)twilio.{0,20}["\']([a-f0-9]{32})["\']')),
    ("GitHub Token",            re.compile(r'ghp_[0-9a-zA-Z]{36}')),
    ("GitHub OAuth",            re.compile(r'gho_[0-9a-zA-Z]{36}')),
    ("Slack Token",             re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}')),
    ("Slack Webhook",           re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+')),
    ("Google API Key",          re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("Firebase URL",            re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com')),
    ("Firebase API Key",        re.compile(r'(?i)firebase.{0,20}["\']([A-Za-z0-9\-_]{39})["\']')),
    ("Heroku API Key",          re.compile(r'(?i)heroku.{0,20}["\']([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})["\']')),
    ("JWT Token",               re.compile(r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*')),
    ("Basic Auth Header",       re.compile(r'(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}')),
    ("Bearer Token Header",     re.compile(r'(?i)Authorization:\s*Bearer\s+[A-Za-z0-9\-_.~+/=]{10,}')),
    ("Connection String (SQL)", re.compile(r'(?i)(Server|Host)=[^;]+;.{0,40}(Password|Pwd)=[^;\'"]+')),
    ("MongoDB URI",             re.compile(r'mongodb(\+srv)?://[^:]+:[^@]+@[^\s"\'<>]+')),
    ("PostgreSQL DSN",          re.compile(r'postgres(?:ql)?://[^:]+:[^@]+@[^\s"\'<>]+')),
    ("MySQL DSN",               re.compile(r'mysql://[^:]+:[^@]+@[^\s"\'<>]+')),
    ("Private Key Header",      re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ("Email + Password Combo",  re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\s*[,;:]\s*[^\s"\']{8,}')),
    ("IP + Port (internal)",    re.compile(r'(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d+\.\d+:\d{2,5}')),
    ("process.env inlined",     re.compile(r'process\.env\.[A-Z_]{3,}\s*=\s*["\'][^"\']{4,}["\']')),
]

# ---------------------------------------------------------------------------
# Entropy analysis
# ---------------------------------------------------------------------------

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def find_high_entropy_strings(content: str, min_length: int = 20) -> list[dict]:
    """Find strings with high Shannon entropy -- likely secrets or tokens."""
    # Match quoted strings of reasonable length
    candidates = re.findall(r'["\']([A-Za-z0-9+/=_\-]{%d,80})["\']' % min_length, content)
    findings = []
    for candidate in set(candidates):
        entropy = shannon_entropy(candidate)
        if entropy >= ENTROPY_THRESHOLD:
            findings.append({"value": candidate, "entropy": round(entropy, 2)})
    return findings

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def fetch(url: str, session: requests.Session, timeout: int = DEFAULT_TIMEOUT) -> requests.Response | None:
    try:
        resp = session.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        return resp
    except requests.RequestException as e:
        console.print(f"  [yellow]WARN[/yellow] Could not fetch {url}: {e}")
        return None


def extract_asset_urls(base_url: str, html: str) -> list[str]:
    """Extract JS, JSON, and other asset URLs from an HTML page."""
    soup = BeautifulSoup(html, "html.parser")
    urls = set()

    # <script src="...">
    for tag in soup.find_all("script", src=True):
        urls.add(urljoin(base_url, tag["src"]))

    # <link href="..."> (for .map files that might slip in)
    for tag in soup.find_all("link", href=True):
        href = tag["href"]
        if any(href.endswith(ext) for ext in TARGET_EXTENSIONS):
            urls.add(urljoin(base_url, href))

    # Inline script content -- scan directly
    inline_scripts = []
    for tag in soup.find_all("script", src=False):
        if tag.string:
            inline_scripts.append(tag.string)

    return list(urls), inline_scripts


def get_same_origin_urls(base_url: str) -> str:
    """Return the origin (scheme + netloc) of a URL."""
    parsed = urlparse(base_url)
    return f"{parsed.scheme}://{parsed.netloc}"

# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def scan_content(content: str, source_label: str) -> list[dict]:
    findings = []

    # Regex patterns
    for pattern_name, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(content):
            matched_text = match.group(0)
            # Get surrounding context (100 chars each side)
            start  = max(0, match.start() - 80)
            end    = min(len(content), match.end() + 80)
            context = content[start:end].replace("\n", " ").strip()
            findings.append({
                "source":    source_label,
                "type":      pattern_name,
                "match":     matched_text[:120],
                "context":   context[:200],
                "method":    "regex",
                "severity":  classify_severity(pattern_name),
            })

    # Entropy analysis
    for item in find_high_entropy_strings(content):
        findings.append({
            "source":   source_label,
            "type":     f"High Entropy String (entropy={item['entropy']})",
            "match":    item["value"][:120],
            "context":  "",
            "method":   "entropy",
            "severity": "MEDIUM",
        })

    return findings


def classify_severity(pattern_name: str) -> str:
    critical = {"AWS Access Key", "AWS Secret Key", "Stripe Live Key", "Private Key Header",
                "MongoDB URI", "PostgreSQL DSN", "MySQL DSN", "Connection String (SQL)",
                "JWT Token", "Generic Password"}
    high     = {"GitHub Token", "Slack Token", "Google API Key", "Firebase API Key",
                "SendGrid API Key", "Bearer Token Header", "Basic Auth Header",
                "Email + Password Combo"}
    if pattern_name in critical:
        return "CRITICAL"
    if pattern_name in high:
        return "HIGH"
    return "MEDIUM"

# ---------------------------------------------------------------------------
# Source map detection
# ---------------------------------------------------------------------------

def check_source_maps(js_urls: list[str], session: requests.Session) -> list[str]:
    found_maps = []
    for url in js_urls:
        map_url = url + ".map"
        resp = fetch(map_url, session)
        if resp and resp.status_code == 200:
            try:
                data = json.loads(resp.text)
                if "sources" in data or "sourcesContent" in data:
                    found_maps.append(map_url)
            except json.JSONDecodeError:
                pass
    return found_maps

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

SEVERITY_COLOR = {
    "CRITICAL": "[bold red]",
    "HIGH":     "[bold yellow]",
    "MEDIUM":   "[yellow]",
}

def print_findings(findings: list[dict]):
    if not findings:
        console.print("\n[bold green]No secrets found.[/bold green]")
        return

    table = Table(title=f"\n[bold]Findings ({len(findings)} total)[/bold]", show_lines=True)
    table.add_column("Severity",  style="bold", width=9)
    table.add_column("Type",      width=28)
    table.add_column("Source",    width=40)
    table.add_column("Match",     width=50)
    table.add_column("Method",    width=8)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    sorted_findings = sorted(findings, key=lambda x: severity_order.get(x["severity"], 3))

    for f in sorted_findings:
        color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "white"}.get(f["severity"], "white")
        table.add_row(
            f"[{color}]{f['severity']}[/{color}]",
            f["type"],
            f["source"][-40:],
            f["match"][:50],
            f["method"],
        )

    console.print(table)


def save_json_report(findings: list[dict], output_path: str):
    with open(output_path, "w") as fh:
        json.dump(findings, fh, indent=2)
    console.print(f"\n[green]Report saved to {output_path}[/green]")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(target_url: str, output: str | None, delay: float, check_wordlist: bool, same_origin_only: bool):
    session  = requests.Session()
    findings = []
    js_urls  = []
    origin   = get_same_origin_urls(target_url)

    console.rule(f"[bold blue]js-secret-scanner[/bold blue]")
    console.print(f"Target: [cyan]{target_url}[/cyan]")
    console.print(f"Origin filter: {'on' if same_origin_only else 'off'}")
    console.print()

    # Step 1: Fetch homepage
    console.print("[*] Fetching target page...")
    resp = fetch(target_url, session)
    if not resp or resp.status_code != 200:
        console.print("[red]Failed to fetch target. Aborting.[/red]")
        sys.exit(1)

    asset_urls, inline_scripts = extract_asset_urls(target_url, resp.text)

    # Step 2: Scan inline scripts
    for i, script in enumerate(inline_scripts):
        label = f"inline-script-{i}"
        console.print(f"  [dim]Scanning {label}[/dim]")
        findings.extend(scan_content(script, label))

    # Step 3: Filter and download assets
    console.print(f"\n[*] Found {len(asset_urls)} asset URLs. Filtering...")
    scannable = []
    for url in asset_urls:
        if same_origin_only and not url.startswith(origin):
            continue
        if any(url.split("?")[0].endswith(ext) for ext in TARGET_EXTENSIONS):
            scannable.append(url)

    console.print(f"  {len(scannable)} files to scan after filter.")

    for url in scannable:
        console.print(f"  [dim]Fetching {url[-60:]}[/dim]")
        r = fetch(url, session)
        time.sleep(delay)
        if not r or r.status_code != 200:
            continue

        content = r.text

        # Beautify JS before scanning
        if url.split("?")[0].endswith(".js"):
            js_urls.append(url)
            try:
                content = jsbeautifier.beautify(content)
            except Exception:
                pass  # scan raw if beautify fails

        findings.extend(scan_content(content, url))

    # Step 4: Check for source maps
    console.print("\n[*] Checking for exposed source maps...")
    maps = check_source_maps(js_urls, session)
    if maps:
        for m in maps:
            console.print(f"  [bold yellow]SOURCE MAP FOUND:[/bold yellow] {m}")
            findings.append({
                "source":   m,
                "type":     "Exposed Source Map",
                "match":    m,
                "context":  "Source map exposes original unminified source code",
                "method":   "detection",
                "severity": "HIGH",
            })
    else:
        console.print("  No source maps found.")

    # Step 5: Wordlist probe
    if check_wordlist:
        console.print("\n[*] Probing common sensitive paths...")
        for path in WORDLIST_PATHS:
            url = urljoin(origin, path)
            r   = fetch(url, session)
            time.sleep(delay)
            if not r:
                continue
            status = r.status_code
            icon = "[green]200[/green]" if status == 200 else f"[dim]{status}[/dim]"
            console.print(f"  {icon}  {url}")
            if status == 200 and len(r.text) > 10:
                findings.extend(scan_content(r.text, url))

    # Step 6: Results
    print_findings(findings)

    if output:
        save_json_report(findings, output)

    summary_color = "red" if any(f["severity"] == "CRITICAL" for f in findings) else \
                    "yellow" if any(f["severity"] == "HIGH" for f in findings) else "green"
    console.print(f"\n[{summary_color}]Scan complete. {len(findings)} finding(s).[/{summary_color}]")


def main():
    parser = argparse.ArgumentParser(
        description="Scan a web page for hardcoded secrets in JS/JSON/config files.",
        epilog="For authorized security research and bug bounty use only."
    )
    parser.add_argument("url",              help="Target URL (e.g. https://target.com)")
    parser.add_argument("-o", "--output",   help="Save findings to JSON file", default=None)
    parser.add_argument("--delay",          help="Delay between requests in seconds (default: 0.5)",
                        type=float, default=DEFAULT_DELAY)
    parser.add_argument("--wordlist",       help="Probe common sensitive paths (default: off)",
                        action="store_true")
    parser.add_argument("--all-origins",    help="Scan third-party JS files too (default: same-origin only)",
                        action="store_true")
    args = parser.parse_args()

    run(
        target_url       = args.url,
        output           = args.output,
        delay            = args.delay,
        check_wordlist   = args.wordlist,
        same_origin_only = not args.all_origins,
    )


if __name__ == "__main__":
    main()
