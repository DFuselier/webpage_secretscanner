# js-secret-scanner

A Python tool for security researchers and bug bounty hunters that crawls a
target web page, downloads JavaScript and configuration files, beautifies
minified code, and scans for hardcoded secrets using regex pattern matching
and Shannon entropy analysis.

> **For authorized security research and bug bounty use only.**
> Only run this tool against targets you have explicit permission to test.

---

## What It Does

1. Fetches the target URL and parses all asset links from the HTML
2. Scans inline `<script>` blocks directly
3. Downloads same-origin JS, JSON, YAML, and config files
4. Beautifies minified JS before scanning (greatly improves context readability)
5. Applies 30+ regex patterns for known secret formats (AWS, GitHub, Stripe, JWT, etc.)
6. Runs Shannon entropy analysis to catch high-randomness strings that don't
   match a known pattern (custom service accounts, internal tokens, etc.)
7. Checks for exposed source maps (.js.map) -- these reconstruct original
   unminified source code and are a high-value finding on their own
8. Optionally probes common sensitive paths (/.env, /config.json, /swagger.json, etc.)

---

## Installation

```bash
# Clone or copy the files into a directory
cd js-secret-scanner

# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

Tested on Python 3.11+. Works on Kali Linux, macOS, and Windows WSL.

---

## Usage

The scanner has two subcommands: `live` (fetches a target URL) and `har`
(fully offline -- reads a captured HAR file with zero outbound requests).

### Live mode -- basic scan

```bash
python scanner.py live https://target.com
```

### Live mode -- full options

```bash
python scanner.py live https://target.com --wordlist --delay 1.0 -o report.json
```

### HAR mode -- fully passive, zero requests (recommended for authenticated sessions)

```bash
# 1. In Chrome/Edge: open DevTools -> Network tab -> browse the target while logged in
# 2. Right-click any request -> "Copy all as HAR (sanitized)"
# 3. Paste into a file: network.har
# 4. Run:
python scanner.py har network.har -o report.json
```

### Include third-party JS (off by default)

```bash
python scanner.py live https://target.com --all-origins
python scanner.py har network.har --all-origins
```

---

## Output

Findings are grouped by category and printed as color-coded tables:

| Category | What It Contains |
|----------|-----------------|
| Secrets | Regex and entropy matches for credentials, keys, tokens |
| WordPress Users | Usernames and slugs from the WP REST API |
| Interesting Comments | Developer comments containing sensitive keywords |
| Discovered Endpoints | API paths and routes extracted from JS |
| Tracking IDs | GTM, GA, Facebook Pixel, Sentry DSN, etc. |
| Header Analysis | Missing security headers and tech fingerprints |

| Severity | Examples |
|----------|----------|
| CRITICAL | AWS keys, DB connection strings, private keys, JWT tokens |
| HIGH | GitHub tokens, Slack tokens, Google API keys, source maps |
| MEDIUM | High entropy strings, generic patterns, WP users |
| LOW | Missing security headers, developer comments |
| INFO | Endpoints, tracking IDs, fingerprint headers |

JSON report fields: `category`, `source`, `type`, `match`, `context`, `method`, `severity`

---

## Detected Secret Types

### Service-Specific
- AWS Access Key and Secret Key
- Stripe live and test keys (sk_live_, sk_test_, pk_live_)
- SendGrid, Mailgun, Twilio API keys
- GitHub personal access tokens (ghp_, gho_)
- Slack tokens and webhooks (xox*, hooks.slack.com)
- Google API keys (AIza...)
- Firebase URLs and API keys
- Heroku API keys

### Generic Patterns
- Passwords and secrets assigned in code (password=, secret=, etc.)
- JWT tokens (eyJ...)
- Authorization headers (Basic, Bearer)
- Database connection strings (PostgreSQL, MySQL, MongoDB)
- Private key PEM headers
- Email + password combinations
- process.env values inlined by bundlers (webpack, Vite, etc.)
- Internal IP:port combinations

### Heuristic
- High Shannon entropy strings (entropy >= 4.2) -- catches custom tokens
  that don't match a known pattern, exactly like the Bain service account

---

## Source Map Detection

If a `.js.map` file exists alongside a JS bundle, the tool flags it as a HIGH
severity finding. Source maps reconstruct original, unminified source code
including developer comments, variable names, and file structure. They are
separate from the secret scan results but are often more valuable than any
individual credential match.

Check for maps manually:
```bash
curl -I https://target.com/static/js/main.abc123.js.map
```

---

## Complementary Tools

This tool handles the discovery and pattern-matching phase. For deeper work,
combine it with:

- `katana` (ProjectDiscovery) -- JS-aware crawler to find more asset URLs
- `trufflehog` -- entropy + credential verification against live services
- `gitleaks` -- broader secret scanning including git history
- `jsluice` -- structured secret and endpoint extraction from JS
- `nuclei` (ProjectDiscovery) -- template-based scanning for exposed configs
- Burp Suite -- proxy all traffic and search responses with regex

---

## Limitations

- Does not execute JavaScript -- dynamically loaded assets (React lazy imports,
  fetch() calls that happen post-load) will not be captured. Use Burp or a
  headless browser to capture those.
- Does not follow pagination or authenticated routes -- run logged-in HAR
  exports through the scanner manually for post-auth coverage.
- Rate of false positives increases with `--all-origins` due to third-party
  obfuscated bundles scoring high on entropy.

---

## Further Reading

See `FINDINGS.md` in this directory for a full write-up of the techniques,
methodology, and educational context behind this tool.

---

## Legal

This tool is intended for use against systems you own or have written
authorization to test. Unauthorized use against systems you do not own is
illegal. The author assumes no liability for misuse.
