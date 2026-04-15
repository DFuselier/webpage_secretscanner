#!/usr/bin/env python3
"""
js-secret-scanner
-----------------
Crawls a target URL (or reads a HAR file), downloads JS/JSON/config files,
beautifies minified code, and passively scans for:

  - Hardcoded secrets via regex patterns and Shannon entropy
  - Exposed source maps
  - API endpoints and internal paths embedded in JS
  - Developer comments left in HTML and JS
  - Security header gaps and server fingerprints
  - Third-party tracking IDs (GTM, GA, CookieYes, etc.)
  - WordPress user enumeration via the REST API

For authorized security research and bug bounty use only.
"""

import argparse
import base64
import json
import math
import re
import sys
import time
from urllib.parse import urljoin, urlparse

import jsbeautifier
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT   = 10
DEFAULT_DELAY     = 0.5
ENTROPY_THRESHOLD = 4.2

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"
}

TARGET_EXTENSIONS = (
    ".js", ".json", ".map", ".env", ".config",
    ".conf", ".xml", ".yaml", ".yml", ".ts"
)

WORDLIST_PATHS = [
    "/.env", "/.env.production", "/.env.local",
    "/config.json", "/settings.json", "/appsettings.json",
    "/web.config", "/swagger.json", "/openapi.json",
    "/api-docs.json", "/api/swagger.json", "/api/openapi.json",
    "/wp-json/wp/v2/users", "/sitemap.xml", "/robots.txt",
]

# Security headers we want to see -- flag if missing
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Server headers that leak technology info
FINGERPRINT_HEADERS = [
    "Server", "X-Powered-By", "X-Generator", "X-AspNet-Version",
    "X-Runtime", "X-Drupal-Cache", "X-Varnish", "Via",
]

# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("Generic Password",        re.compile(r'(?i)(password|passwd|pass|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']')),
    ("Generic Secret",          re.compile(r'(?i)(secret|api_secret|client_secret)\s*[:=]\s*["\']([^"\']{8,})["\']')),
    ("Generic API Key",         re.compile(r'(?i)(api_key|apikey|api-key)\s*[:=]\s*["\']([^"\']{8,})["\']')),
    ("Generic Token",           re.compile(r'(?i)(token|auth_token|access_token|bearer)\s*[:=]\s*["\']([^"\']{8,})["\']')),
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
# Third-party ID patterns
# ---------------------------------------------------------------------------

TRACKING_PATTERNS = [
    ("Google Tag Manager",   re.compile(r'GTM-[A-Z0-9]{4,10}')),
    ("Google Analytics GA4", re.compile(r'G-[A-Z0-9]{8,12}')),
    ("Google Analytics UA",  re.compile(r'UA-\d{6,10}-\d{1,3}')),
    ("Facebook Pixel",       re.compile(r'fbq\s*\(\s*["\']init["\']\s*,\s*["\'](\d{10,20})["\']')),
    ("Hotjar",               re.compile(r'hjid\s*[:=]\s*(\d{6,10})')),
    ("Segment Write Key",    re.compile(r'analytics\.load\s*\(\s*["\']([A-Za-z0-9]{20,})["\']')),
    ("Intercom App ID",      re.compile(r'app_id\s*[:=]\s*["\']([a-z0-9]{8,})["\']')),
    ("CookieYes Client ID",  re.compile(r'cdn-cookieyes\.com/client_data/([a-f0-9]{32})')),
    ("Mixpanel Token",       re.compile(r'mixpanel\.init\s*\(\s*["\']([a-f0-9]{32})["\']')),
    ("Sentry DSN",           re.compile(r'https://[a-f0-9]{32}@[a-z0-9.]+sentry\.io/\d+')),
    ("Datadog Client Token", re.compile(r'(?i)datadog.{0,30}["\']([a-f0-9]{32,40})["\']')),
]

# ---------------------------------------------------------------------------
# Endpoint patterns
# ---------------------------------------------------------------------------

ENDPOINT_PATTERNS = [
    re.compile(r'["\`](/api/[^\s"\'`\)]{3,80})["\`]'),
    re.compile(r'["\`](/v\d+/[^\s"\'`\)]{3,80})["\`]'),
    re.compile(r'["\`](/graphql[^\s"\'`\)]{0,40})["\`]'),
    re.compile(r'["\`](/admin[^\s"\'`\)]{0,60})["\`]'),
    re.compile(r'["\`](/internal[^\s"\'`\)]{0,60})["\`]'),
    re.compile(r'["\`](/wp-json[^\s"\'`\)]{0,60})["\`]'),
    re.compile(r'["\`](/_[^\s"\'`\)]{3,60})["\`]'),
    re.compile(r'fetch\s*\(\s*["\`]([^"\'`\)]{10,120})["\`]'),
    re.compile(r'axios\.[a-z]+\s*\(\s*["\`]([^"\'`\)]{10,120})["\`]'),
    re.compile(r'\.get\s*\(\s*["\`](/[^"\'`\)]{5,80})["\`]'),
    re.compile(r'\.post\s*\(\s*["\`](/[^"\'`\)]{5,80})["\`]'),
]

# ---------------------------------------------------------------------------
# Comment patterns
# ---------------------------------------------------------------------------

HTML_COMMENT_RE = re.compile(r'<!--(.*?)-->', re.DOTALL)
JS_COMMENT_RE   = re.compile(
    r'(?://([^\n]{10,})|/\*(.*?)\*/)',
    re.DOTALL
)

COMMENT_KEYWORDS = re.compile(
    r'(?i)(todo|fixme|hack|password|credential|secret|key|token|auth|'
    r'staging|prod|production|debug|test|admin|internal|private|'
    r'hardcod|remove|cleanup|temp|temporary|bypass|workaround)'
)

# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def find_high_entropy_strings(content: str, min_length: int = 20) -> list[dict]:
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

def fetch(url: str, session: requests.Session, timeout: int = DEFAULT_TIMEOUT):
    try:
        return session.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        console.print(f"  [yellow]WARN[/yellow] {url}: {e}")
        return None


def get_origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"

# ---------------------------------------------------------------------------
# HAR parsing
# ---------------------------------------------------------------------------

def load_har(har_path: str) -> tuple[list[dict], str]:
    with open(har_path) as fh:
        har = json.load(fh)

    entries  = []
    base_url = ""

    for entry in har["log"]["entries"]:
        url    = entry["request"]["url"]
        status = entry["response"]["status"]
        body   = entry["response"].get("content", {})
        text   = body.get("text", "")
        enc    = body.get("encoding", "")

        if enc == "base64" and text:
            try:
                text = base64.b64decode(text).decode("utf-8", errors="replace")
            except Exception:
                text = ""

        resp_headers = {
            h["name"].lower(): h["value"]
            for h in entry["response"].get("headers", [])
        }

        if not base_url:
            base_url = get_origin(url)

        entries.append({
            "url":     url,
            "status":  status,
            "content": text,
            "headers": resp_headers,
        })

    console.print(f"  Loaded [cyan]{len(entries)}[/cyan] entries from HAR.")
    return entries, base_url

# ---------------------------------------------------------------------------
# Asset extraction
# ---------------------------------------------------------------------------

def extract_asset_urls(base_url: str, html: str) -> tuple[list[str], list[str]]:
    soup   = BeautifulSoup(html, "html.parser")
    urls   = set()
    inline = []

    for tag in soup.find_all("script", src=True):
        urls.add(urljoin(base_url, tag["src"]))

    for tag in soup.find_all("link", href=True):
        href = tag["href"]
        if any(href.split("?")[0].endswith(ext) for ext in TARGET_EXTENSIONS):
            urls.add(urljoin(base_url, href))

    for tag in soup.find_all("script", src=False):
        if tag.string:
            inline.append(tag.string)

    return list(urls), inline


def extract_inline_scripts(html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    return [tag.string for tag in soup.find_all("script", src=False) if tag.string]

# ---------------------------------------------------------------------------
# Scanning functions
# ---------------------------------------------------------------------------

def scan_secrets(content: str, source: str) -> list[dict]:
    findings = []

    for name, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(content):
            start   = max(0, match.start() - 80)
            end     = min(len(content), match.end() + 80)
            context = content[start:end].replace("\n", " ").strip()
            findings.append({
                "category": "secret",
                "source":   source,
                "type":     name,
                "match":    match.group(0)[:120],
                "context":  context[:200],
                "method":   "regex",
                "severity": classify_severity(name),
            })

    for item in find_high_entropy_strings(content):
        findings.append({
            "category": "secret",
            "source":   source,
            "type":     f"High Entropy String (entropy={item['entropy']})",
            "match":    item["value"][:120],
            "context":  "",
            "method":   "entropy",
            "severity": "MEDIUM",
        })

    return findings


def scan_endpoints(content: str, source: str) -> list[dict]:
    found = set()
    for pattern in ENDPOINT_PATTERNS:
        for match in pattern.finditer(content):
            path = match.group(1).strip()
            if path and len(path) > 3:
                found.add(path)
    return [
        {
            "category": "endpoint",
            "source":   source,
            "type":     "API Endpoint",
            "match":    path,
            "context":  "",
            "method":   "regex",
            "severity": "INFO",
        }
        for path in sorted(found)
    ]


def scan_comments(content: str, source: str, is_html: bool = False) -> list[dict]:
    findings = []
    pattern  = HTML_COMMENT_RE if is_html else JS_COMMENT_RE

    for match in pattern.finditer(content):
        text = next((g for g in match.groups() if g is not None), "").strip()
        if len(text) < 10:
            continue
        if COMMENT_KEYWORDS.search(text):
            findings.append({
                "category": "comment",
                "source":   source,
                "type":     "Interesting Comment",
                "match":    text[:200].replace("\n", " "),
                "context":  "",
                "method":   "regex",
                "severity": "LOW",
            })

    return findings


def scan_tracking_ids(content: str, source: str) -> list[dict]:
    findings = []
    seen     = set()
    for name, pattern in TRACKING_PATTERNS:
        for match in pattern.finditer(content):
            value = match.group(1) if match.lastindex else match.group(0)
            key   = (name, value)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "category": "tracking",
                    "source":   source,
                    "type":     f"Tracking ID: {name}",
                    "match":    value[:80],
                    "context":  "",
                    "method":   "regex",
                    "severity": "INFO",
                })
    return findings


def analyze_headers(headers: dict, source: str) -> list[dict]:
    findings    = []
    header_keys = {k.lower() for k in headers}

    for header in SECURITY_HEADERS:
        if header.lower() not in header_keys:
            findings.append({
                "category": "headers",
                "source":   source,
                "type":     f"Missing Header: {header}",
                "match":    "(not present)",
                "context":  "",
                "method":   "detection",
                "severity": "LOW",
            })

    for header in FINGERPRINT_HEADERS:
        for k, v in headers.items():
            if k.lower() == header.lower():
                findings.append({
                    "category": "headers",
                    "source":   source,
                    "type":     f"Tech Fingerprint: {header}",
                    "match":    v[:80],
                    "context":  "",
                    "method":   "detection",
                    "severity": "INFO",
                })

    return findings


def classify_severity(name: str) -> str:
    critical = {
        "AWS Access Key", "AWS Secret Key", "Stripe Live Key", "Private Key Header",
        "MongoDB URI", "PostgreSQL DSN", "MySQL DSN", "Connection String (SQL)",
        "JWT Token", "Generic Password",
    }
    high = {
        "GitHub Token", "Slack Token", "Google API Key", "Firebase API Key",
        "SendGrid API Key", "Bearer Token Header", "Basic Auth Header",
        "Email + Password Combo",
    }
    if name in critical:
        return "CRITICAL"
    if name in high:
        return "HIGH"
    return "MEDIUM"

# ---------------------------------------------------------------------------
# Source map detection
# ---------------------------------------------------------------------------

def check_source_maps(js_urls: list[str], session: requests.Session) -> list[str]:
    found = []
    for url in js_urls:
        map_url = url.split("?")[0] + ".map"
        resp    = fetch(map_url, session)
        if resp and resp.status_code == 200:
            try:
                data = json.loads(resp.text)
                if "sources" in data or "sourcesContent" in data:
                    found.append(map_url)
            except json.JSONDecodeError:
                pass
    return found

# ---------------------------------------------------------------------------
# WordPress user enumeration
# ---------------------------------------------------------------------------

def enumerate_wp_users(origin: str, session: requests.Session, delay: float) -> list[dict]:
    url  = urljoin(origin, "/wp-json/wp/v2/users")
    resp = fetch(url, session)
    time.sleep(delay)

    if not resp or resp.status_code != 200:
        return []

    try:
        users = json.loads(resp.text)
        if not isinstance(users, list) or not users:
            return []
    except json.JSONDecodeError:
        return []

    findings = []
    for user in users:
        name = user.get("name", "")
        slug = user.get("slug", "")
        uid  = user.get("id", "")
        link = user.get("link", "")
        findings.append({
            "category": "wp_user",
            "source":   url,
            "type":     "WordPress User Enumerated",
            "match":    f"id={uid} name={name!r} slug={slug!r}",
            "context":  link,
            "method":   "detection",
            "severity": "MEDIUM",
        })

    if findings:
        console.print(f"  [bold yellow]{len(findings)} WordPress user(s) found.[/bold yellow]")

    return findings

# ---------------------------------------------------------------------------
# Process one file through all passive scanners
# ---------------------------------------------------------------------------

def process_file(url: str, content: str, headers: dict) -> list[dict]:
    findings  = []
    clean_url = url.split("?")[0]
    is_js     = clean_url.endswith(".js")
    is_html   = clean_url.endswith((".html", ".htm")) or \
                "text/html" in headers.get("content-type", "")

    if is_js:
        try:
            content = jsbeautifier.beautify(content)
        except Exception:
            pass

    findings += scan_secrets(content, url)
    findings += scan_endpoints(content, url)
    findings += scan_comments(content, url, is_html=is_html)
    findings += scan_tracking_ids(content, url)
    findings += analyze_headers(headers, url)

    return findings

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

CATEGORY_TITLES = {
    "secret":   "Secrets",
    "wp_user":  "WordPress Users",
    "comment":  "Interesting Comments",
    "endpoint": "Discovered Endpoints",
    "tracking": "Tracking IDs",
    "headers":  "Header Analysis",
}

SEVERITY_COLOR = {
    "CRITICAL": "red",
    "HIGH":     "yellow",
    "MEDIUM":   "white",
    "LOW":      "dim",
    "INFO":     "cyan",
}


def print_findings(all_findings: list[dict]):
    categories    = {}
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    for f in all_findings:
        categories.setdefault(f["category"], []).append(f)

    if not categories:
        console.print("\n[bold green]No findings.[/bold green]")
        return

    for cat in CATEGORY_TITLES:
        items = categories.get(cat, [])
        if not items:
            continue

        table = Table(
            title=f"[bold]{CATEGORY_TITLES[cat]} ({len(items)})[/bold]",
            show_lines=True
        )
        table.add_column("Severity", width=9)
        table.add_column("Type",     width=30)
        table.add_column("Source",   width=38)
        table.add_column("Match",    width=52)

        for f in sorted(items, key=lambda x: severity_rank.get(x["severity"], 9)):
            color = SEVERITY_COLOR.get(f["severity"], "white")
            table.add_row(
                f"[{color}]{f['severity']}[/{color}]",
                f["type"],
                f["source"][-38:],
                f["match"][:52],
            )

        console.print(table)


def save_json_report(findings: list[dict], path: str):
    with open(path, "w") as fh:
        json.dump(findings, fh, indent=2)
    console.print(f"\n[green]Report saved to {path}[/green]")


def finish(findings: list[dict], output: str | None):
    print_findings(findings)

    total    = len(findings)
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high     = sum(1 for f in findings if f.get("severity") == "HIGH")
    color    = "red" if critical else "yellow" if high else "green"

    console.print(Panel(
        f"[{color}]Total: {total}  |  Critical: {critical}  |  High: {high}[/{color}]",
        title="Scan Complete",
        expand=False,
    ))

    if output:
        save_json_report(findings, output)

# ---------------------------------------------------------------------------
# Live mode
# ---------------------------------------------------------------------------

def dump_file(content: str, url: str, dump_dir: str):
    """Save a fetched file to the dump directory for external tool analysis."""
    import hashlib, os
    os.makedirs(dump_dir, exist_ok=True)
    parsed   = urlparse(url)
    filename = parsed.path.rstrip("/").split("/")[-1].split("?")[0] or "index"
    # Avoid collisions with a short hash prefix
    prefix   = hashlib.md5(url.encode()).hexdigest()[:6]
    safe     = re.sub(r'[^\w.\-]', '_', filename)
    path     = os.path.join(dump_dir, f"{prefix}_{safe}")
    with open(path, "w", errors="replace") as fh:
        fh.write(content)
    return path


def run_live(target_url: str, output: str | None, delay: float,
             check_wordlist: bool, same_origin_only: bool, dump_dir: str | None = None):

    session  = requests.Session()
    findings = []
    js_urls  = []
    origin   = get_origin(target_url)

    console.rule("[bold blue]js-secret-scanner[/bold blue]")
    console.print(f"Mode:   [cyan]live[/cyan]")
    console.print(f"Target: [cyan]{target_url}[/cyan]")
    if dump_dir:
        console.print(f"Dump:   [cyan]{dump_dir}[/cyan]")
    console.print()

    # Fetch homepage
    console.print("[*] Fetching target page...")
    resp = fetch(target_url, session)
    if not resp or resp.status_code != 200:
        console.print("[red]Failed to fetch target. Aborting.[/red]")
        sys.exit(1)

    findings += analyze_headers(dict(resp.headers), target_url)
    findings += scan_comments(resp.text, target_url, is_html=True)
    findings += scan_tracking_ids(resp.text, target_url)

    asset_urls, inline_scripts = extract_asset_urls(target_url, resp.text)

    for i, script in enumerate(inline_scripts):
        label = f"inline-script-{i}"
        findings += scan_secrets(script, label)
        findings += scan_endpoints(script, label)
        findings += scan_comments(script, label)
        findings += scan_tracking_ids(script, label)

    # Filter and download assets
    console.print(f"\n[*] Found {len(asset_urls)} asset URLs. Filtering...")
    scannable = [
        u for u in asset_urls
        if (not same_origin_only or u.startswith(origin))
        and any(u.split("?")[0].endswith(ext) for ext in TARGET_EXTENSIONS)
    ]
    console.print(f"  {len(scannable)} in-scope files to scan.")

    for url in scannable:
        console.print(f"  [dim]Fetching {url[-65:]}[/dim]")
        r = fetch(url, session)
        time.sleep(delay)
        if not r or r.status_code != 200:
            continue
        if url.split("?")[0].endswith(".js"):
            js_urls.append(url)
        if dump_dir:
            dump_file(r.text, url, dump_dir)
        findings += process_file(url, r.text, dict(r.headers))

    # Source maps
    console.print("\n[*] Checking for exposed source maps...")
    maps = check_source_maps(js_urls, session)
    for m in maps:
        console.print(f"  [bold yellow]SOURCE MAP:[/bold yellow] {m}")
        findings.append({
            "category": "secret",
            "source":   m,
            "type":     "Exposed Source Map",
            "match":    m,
            "context":  "Reconstructs original unminified source",
            "method":   "detection",
            "severity": "HIGH",
        })
    if not maps:
        console.print("  None found.")

    # Optional wordlist
    if check_wordlist:
        console.print("\n[*] Probing sensitive paths...")
        for path in WORDLIST_PATHS:
            url = urljoin(origin, path)
            r   = fetch(url, session)
            time.sleep(delay)
            if not r:
                continue
            icon = "[green]200[/green]" if r.status_code == 200 else f"[dim]{r.status_code}[/dim]"
            console.print(f"  {icon}  {url}")
            if r.status_code == 200 and len(r.text) > 10:
                findings += process_file(url, r.text, dict(r.headers))

    # WordPress user enumeration
    console.print("\n[*] Checking for WordPress user enumeration...")
    wp = enumerate_wp_users(origin, session, delay)
    findings += wp
    if not wp:
        console.print("  Not WordPress or endpoint is protected.")

    finish(findings, output)

# ---------------------------------------------------------------------------
# HAR mode
# ---------------------------------------------------------------------------

def run_har(har_path: str, output: str | None, same_origin_only: bool):
    console.rule("[bold blue]js-secret-scanner[/bold blue]")
    console.print(f"Mode: [cyan]HAR[/cyan]  ({har_path})\n")

    console.print("[*] Loading HAR...")
    entries, origin = load_har(har_path)

    findings = []
    js_urls  = set()
    har_urls = set()

    for entry in entries:
        url     = entry["url"]
        content = entry["content"]
        headers = entry["headers"]
        status  = entry["status"]
        clean   = url.split("?")[0]

        har_urls.add(clean)

        if same_origin_only and not url.startswith(origin):
            continue
        if status not in (200, 304):
            continue
        if not content:
            continue

        ct      = headers.get("content-type", "")
        is_html = "text/html" in ct or clean.endswith((".html", ".htm"))
        is_js   = clean.endswith(".js")

        if is_html:
            findings += scan_comments(content, url, is_html=True)
            findings += scan_tracking_ids(content, url)
            findings += analyze_headers(headers, url)
            for i, script in enumerate(extract_inline_scripts(content)):
                label = f"{url}#inline-{i}"
                findings += scan_secrets(script, label)
                findings += scan_endpoints(script, label)
                findings += scan_comments(script, label)

        elif any(clean.endswith(ext) for ext in TARGET_EXTENSIONS):
            if is_js:
                js_urls.add(clean)
            findings += process_file(url, content, headers)

    # Check for source maps present in the HAR
    for js_url in js_urls:
        map_url = js_url + ".map"
        if map_url in har_urls:
            findings.append({
                "category": "secret",
                "source":   map_url,
                "type":     "Exposed Source Map (in HAR)",
                "match":    map_url,
                "context":  "Reconstructs original unminified source",
                "method":   "detection",
                "severity": "HIGH",
            })

    finish(findings, output)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Passive JS/HAR secret and recon scanner.",
        epilog="For authorized security research and bug bounty use only."
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    live = sub.add_parser("live", help="Fetch and scan a live URL")
    live.add_argument("url")
    live.add_argument("-o", "--output",  help="Save findings to JSON")
    live.add_argument("--delay",         type=float, default=DEFAULT_DELAY,
                      help="Seconds between requests (default 0.5)")
    live.add_argument("--wordlist",      action="store_true",
                      help="Probe common sensitive paths")
    live.add_argument("--all-origins",   action="store_true",
                      help="Include third-party JS files")
    live.add_argument("--dump",          default=None, metavar="DIR",
                      help="Save all fetched files to DIR for external tool analysis")

    har = sub.add_parser("har", help="Scan a captured HAR file (fully passive, zero requests)")
    har.add_argument("har_file",         help="Path to .har file")
    har.add_argument("-o", "--output",   help="Save findings to JSON")
    har.add_argument("--all-origins",    action="store_true",
                     help="Include third-party entries")

    args = parser.parse_args()

    if args.mode == "live":
        run_live(
            target_url       = args.url,
            output           = getattr(args, "output", None),
            delay            = args.delay,
            check_wordlist   = args.wordlist,
            same_origin_only = not args.all_origins,
            dump_dir         = getattr(args, "dump", None),
        )
    elif args.mode == "har":
        run_har(
            har_path         = args.har_file,
            output           = getattr(args, "output", None),
            same_origin_only = not args.all_origins,
        )


if __name__ == "__main__":
    main()
