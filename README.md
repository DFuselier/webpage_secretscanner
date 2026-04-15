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

### Basic scan (same-origin JS files only)

```bash
python scanner.py https://target.com
```

### Save findings to a JSON report

```bash
python scanner.py https://target.com -o findings.json
```

### Also probe common sensitive paths (/.env, /swagger.json, etc.)

```bash
python scanner.py https://target.com --wordlist
```

### Include third-party JS files (CDN, analytics, etc.)

```bash
python scanner.py https://target.com --all-origins
```

### Slow down requests (avoid rate limiting)

```bash
python scanner.py https://target.com --delay 1.5
```

### Full example

```bash
python scanner.py https://target.com --wordlist -o report.json --delay 1.0
```

---

## Output

Findings are printed as a color-coded table sorted by severity:

| Severity | Examples |
|----------|----------|
| CRITICAL | AWS keys, database connection strings, private keys, JWT tokens, plaintext passwords |
| HIGH     | GitHub tokens, Slack tokens, Google API keys, Bearer auth headers |
| MEDIUM   | High entropy strings, generic API key patterns, internal IPs |

A JSON report (when `-o` is used) contains each finding with:
- `source` -- the URL or label where the secret was found
- `type` -- the pattern name that matched
- `match` -- the matched string (truncated to 120 chars)
- `context` -- surrounding code for manual review
- `method` -- "regex" or "entropy"
- `severity` -- CRITICAL / HIGH / MEDIUM

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
