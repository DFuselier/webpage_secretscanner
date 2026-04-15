#!/usr/bin/env bash
# analyze.sh
# Passive analysis pipeline -- runs all complementary tools against a
# local directory of already-downloaded files. Zero outbound requests.
#
# Typical workflow:
#   1. python scanner.py live https://target.com --dump ./dump -o scanner.json
#      (or) python scanner.py har network.har -o scanner.json
#   2. ./analyze.sh --dir ./dump --out ./results
#
# For authorized security research and bug bounty use only.

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DUMP_DIR=""
OUT_DIR="./results"
TARGET_URL=""
SKIP_TRUFFLEHOG=false
SKIP_GITLEAKS=false
SKIP_JSLUICE=false
SKIP_SOURCEMAP=false
VERBOSE=false

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
section() { echo -e "\n${BOLD}${CYAN}==> $*${NC}"; }
error()   { echo -e "${RED}[-]${NC} $*"; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
cat <<EOF
${BOLD}analyze.sh${NC} -- Passive multi-tool analysis pipeline

${BOLD}Usage:${NC}
  ./analyze.sh --dir DUMP_DIR [options]

${BOLD}Required:${NC}
  --dir DIR          Directory containing files downloaded by the scanner
                     (produced by: python scanner.py live URL --dump DIR)

${BOLD}Options:${NC}
  --out DIR          Output directory for reports (default: ./results)
  --url URL          Original target URL -- used for context in reports
  --no-trufflehog    Skip TruffleHog
  --no-gitleaks      Skip Gitleaks
  --no-jsluice       Skip jsluice
  --no-sourcemap     Skip source-map-explorer
  --verbose          Show full tool output as it runs
  -h, --help         Show this help

${BOLD}Examples:${NC}
  # Full pipeline after a live scan dump
  python scanner.py live https://target.com --dump ./dump
  ./analyze.sh --dir ./dump --out ./results --url https://target.com

  # HAR workflow -- dump files from HAR first, then analyze
  python extract_har.py network.har --dump ./dump
  ./analyze.sh --dir ./dump --out ./results

  # Skip tools you don't have installed
  ./analyze.sh --dir ./dump --no-sourcemap

EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)         DUMP_DIR="$2";      shift 2 ;;
        --out)         OUT_DIR="$2";       shift 2 ;;
        --url)         TARGET_URL="$2";    shift 2 ;;
        --no-trufflehog) SKIP_TRUFFLEHOG=true; shift ;;
        --no-gitleaks)   SKIP_GITLEAKS=true;   shift ;;
        --no-jsluice)    SKIP_JSLUICE=true;    shift ;;
        --no-sourcemap)  SKIP_SOURCEMAP=true;  shift ;;
        --verbose)     VERBOSE=true;       shift ;;
        -h|--help)     usage; exit 0 ;;
        *) error "Unknown argument: $1"; usage; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------

if [[ -z "$DUMP_DIR" ]]; then
    error "--dir is required."
    usage
    exit 1
fi

if [[ ! -d "$DUMP_DIR" ]]; then
    error "Dump directory does not exist: $DUMP_DIR"
    exit 1
fi

FILE_COUNT=$(find "$DUMP_DIR" -type f | wc -l | tr -d ' ')
if [[ "$FILE_COUNT" -eq 0 ]]; then
    error "No files found in $DUMP_DIR"
    exit 1
fi

mkdir -p "$OUT_DIR"

# ---------------------------------------------------------------------------
# Helper: run a command, tee output, capture exit code safely
# ---------------------------------------------------------------------------

run_tool() {
    local name="$1"; shift
    local out_file="$1"; shift

    if $VERBOSE; then
        "$@" 2>&1 | tee "$out_file" || true
    else
        "$@" > "$out_file" 2>&1 || true
    fi
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║       js-secret-scanner              ║"
echo "  ║       Passive Analysis Pipeline      ║"
echo "  ╚══════════════════════════════════════╝"
echo -e "${NC}"

info "Dump directory : $DUMP_DIR ($FILE_COUNT files)"
info "Output         : $OUT_DIR"
[[ -n "$TARGET_URL" ]] && info "Target URL     : $TARGET_URL"
echo

# Collect JS files specifically (most tools want these)
JS_FILES=$(find "$DUMP_DIR" -type f -name "*.js" 2>/dev/null || true)
MAP_FILES=$(find "$DUMP_DIR" -type f -name "*.map" 2>/dev/null || true)
JS_COUNT=$(echo "$JS_FILES" | grep -c . 2>/dev/null || echo 0)
MAP_COUNT=$(echo "$MAP_FILES" | grep -c . 2>/dev/null || echo 0)

info "JS files  : $JS_COUNT"
info "Map files : $MAP_COUNT"
echo

FINDINGS_SUMMARY=()

# ---------------------------------------------------------------------------
# 1. TruffleHog -- filesystem mode, no verification (passive)
# ---------------------------------------------------------------------------

if ! $SKIP_TRUFFLEHOG; then
    section "TruffleHog (entropy + regex, filesystem mode)"

    if ! command -v trufflehog &>/dev/null; then
        warn "trufflehog not found. Run ./install_tools.sh or use --no-trufflehog"
    else
        OUT_FILE="$OUT_DIR/trufflehog.json"
        info "Scanning $DUMP_DIR..."

        # --no-verification keeps this fully passive -- no live API calls to
        # verify whether credentials are still valid
        trufflehog filesystem "$DUMP_DIR" \
            --json \
            --no-verification \
            2>/dev/null > "$OUT_FILE" || true

        HITS=$(grep -c '"SourceMetadata"' "$OUT_FILE" 2>/dev/null || echo 0)
        info "Results: $HITS potential secret(s) -> $OUT_FILE"
        FINDINGS_SUMMARY+=("TruffleHog: $HITS finding(s)")

        # Pretty-print the top findings if any
        if [[ "$HITS" -gt 0 ]] && command -v python3 &>/dev/null; then
            python3 - "$OUT_FILE" <<'PYEOF'
import json, sys

path = sys.argv[1]
findings = []
with open(path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            pass

seen = set()
for item in findings:
    det = item.get("DetectorName", "Unknown")
    raw = item.get("Raw", "")[:80]
    src = item.get("SourceMetadata", {}).get("Data", {})
    # Flatten source info
    file_info = str(src)[:60]
    key = (det, raw)
    if key not in seen:
        seen.add(key)
        print(f"  [{det}] {raw}  ({file_info})")
PYEOF
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 2. Gitleaks -- detect mode, no-git (runs against files, not a repo)
# ---------------------------------------------------------------------------

if ! $SKIP_GITLEAKS; then
    section "Gitleaks (broad ruleset, file mode)"

    if ! command -v gitleaks &>/dev/null; then
        warn "gitleaks not found. Run ./install_tools.sh or use --no-gitleaks"
    else
        OUT_FILE="$OUT_DIR/gitleaks.json"
        info "Scanning $DUMP_DIR..."

        # detect + --source + --no-git scans files without needing a git repo
        gitleaks detect \
            --source "$DUMP_DIR" \
            --no-git \
            --report-format json \
            --report-path "$OUT_FILE" \
            --redact \
            --exit-code 0 \
            2>/dev/null || true

        if [[ -f "$OUT_FILE" ]]; then
            HITS=$(python3 -c "
import json
try:
    data = json.load(open('$OUT_FILE'))
    print(len(data) if isinstance(data, list) else 0)
except:
    print(0)
" 2>/dev/null || echo 0)
        else
            HITS=0
            echo "[]" > "$OUT_FILE"
        fi

        info "Results: $HITS finding(s) -> $OUT_FILE"
        FINDINGS_SUMMARY+=("Gitleaks: $HITS finding(s)")

        if [[ "$HITS" -gt 0 ]] && command -v python3 &>/dev/null; then
            python3 - "$OUT_FILE" <<'PYEOF'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    seen = set()
    for item in data[:20]:
        rule = item.get("RuleID", "")
        secret = item.get("Secret", "")[:60]
        file_ = item.get("File", "")
        key = (rule, secret)
        if key not in seen:
            seen.add(key)
            print(f"  [{rule}] {secret}  (file: {file_})")
except Exception as e:
    print(f"  Could not parse: {e}")
PYEOF
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 3. jsluice -- structured secret + endpoint extraction
# ---------------------------------------------------------------------------

if ! $SKIP_JSLUICE; then
    section "jsluice (structured secret + endpoint extraction)"

    if ! command -v jsluice &>/dev/null; then
        warn "jsluice not found. Run ./install_tools.sh or use --no-jsluice"
    else
        SECRETS_FILE="$OUT_DIR/jsluice_secrets.json"
        URLS_FILE="$OUT_DIR/jsluice_urls.json"

        if [[ "$JS_COUNT" -eq 0 ]]; then
            warn "No .js files found in dump. Skipping jsluice."
        else
            info "Extracting secrets from $JS_COUNT JS file(s)..."

            # Process each JS file individually and aggregate
            > "$SECRETS_FILE"
            > "$URLS_FILE"

            while IFS= read -r jsfile; do
                [[ -z "$jsfile" ]] && continue
                jsluice secrets < "$jsfile" 2>/dev/null >> "$SECRETS_FILE" || true
                jsluice urls    < "$jsfile" 2>/dev/null >> "$URLS_FILE"    || true
            done <<< "$JS_FILES"

            SECRET_HITS=$(grep -c '{' "$SECRETS_FILE" 2>/dev/null || echo 0)
            URL_HITS=$(grep -c '{' "$URLS_FILE" 2>/dev/null || echo 0)

            info "Secrets: $SECRET_HITS -> $SECRETS_FILE"
            info "URLs/endpoints: $URL_HITS -> $URLS_FILE"
            FINDINGS_SUMMARY+=("jsluice secrets: $SECRET_HITS | endpoints: $URL_HITS")

            if [[ "$SECRET_HITS" -gt 0 ]] && command -v python3 &>/dev/null; then
                python3 - "$SECRETS_FILE" <<'PYEOF'
import json, sys

seen = set()
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            kind  = item.get("kind", "")
            value = str(item.get("value", ""))[:80]
            key   = (kind, value)
            if key not in seen:
                seen.add(key)
                print(f"  [{kind}] {value}")
        except json.JSONDecodeError:
            pass
PYEOF
            fi

            if [[ "$URL_HITS" -gt 0 ]] && command -v python3 &>/dev/null; then
                info "Sample endpoints:"
                python3 - "$URLS_FILE" <<'PYEOF'
import json, sys

seen = set()
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            url = item.get("value", "")
            if url and url not in seen:
                seen.add(url)
                print(f"  {url}")
                if len(seen) >= 20:
                    print("  ... (see full file for all results)")
                    break
        except json.JSONDecodeError:
            pass
PYEOF
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 4. source-map-explorer -- reconstruct source from .map files
# ---------------------------------------------------------------------------

if ! $SKIP_SOURCEMAP; then
    section "source-map-explorer (source map reconstruction)"

    if ! command -v source-map-explorer &>/dev/null; then
        warn "source-map-explorer not found. Run ./install_tools.sh or use --no-sourcemap"
    elif [[ "$MAP_COUNT" -eq 0 ]]; then
        info "No .map files found in dump. Skipping."
    else
        MAP_OUT_DIR="$OUT_DIR/sourcemaps"
        mkdir -p "$MAP_OUT_DIR"
        info "Processing $MAP_COUNT source map(s)..."

        while IFS= read -r mapfile; do
            [[ -z "$mapfile" ]] && continue
            # The corresponding .js file (strip trailing .map)
            jsfile="${mapfile%.map}"
            basename_map=$(basename "$mapfile")

            if [[ -f "$jsfile" ]]; then
                out_html="$MAP_OUT_DIR/${basename_map%.map}.html"
                info "  $basename_map -> $out_html"
                source-map-explorer "$jsfile" "$mapfile" \
                    --html "$out_html" \
                    2>/dev/null || warn "  Could not process $basename_map"
            else
                warn "  JS file not found for map: $mapfile (expected $jsfile)"
            fi
        done <<< "$MAP_FILES"

        HTML_COUNT=$(find "$MAP_OUT_DIR" -name "*.html" 2>/dev/null | wc -l | tr -d ' ')
        info "$HTML_COUNT source tree report(s) generated in $MAP_OUT_DIR"
        FINDINGS_SUMMARY+=("source-map-explorer: $HTML_COUNT HTML report(s)")
        [[ "$HTML_COUNT" -gt 0 ]] && info "Open the HTML files in a browser to browse reconstructed source."
    fi
fi

# ---------------------------------------------------------------------------
# 5. Aggregate and deduplicate all JSON findings
# ---------------------------------------------------------------------------

section "Aggregating results"

python3 - "$OUT_DIR" <<'PYEOF'
import json, os, sys, glob

out_dir = sys.argv[1]
files   = [
    "trufflehog.json",
    "gitleaks.json",
    "jsluice_secrets.json",
]

all_findings = []

for fname in files:
    fpath = os.path.join(out_dir, fname)
    if not os.path.exists(fpath):
        continue
    tool = fname.replace(".json", "")
    with open(fpath) as f:
        content = f.read().strip()
    if not content:
        continue
    # Handle newline-delimited JSON (trufflehog, jsluice) and arrays (gitleaks)
    if content.startswith("["):
        try:
            items = json.loads(content)
            for item in items:
                item["_tool"] = tool
                all_findings.append(item)
        except json.JSONDecodeError:
            pass
    else:
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                item["_tool"] = tool
                all_findings.append(item)
            except json.JSONDecodeError:
                pass

out_path = os.path.join(out_dir, "all_findings.json")
with open(out_path, "w") as f:
    json.dump(all_findings, f, indent=2)

print(f"  Combined report: {out_path} ({len(all_findings)} total entries)")
PYEOF

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo
echo -e "${BOLD}${GREEN}Analysis complete.${NC}"
echo
echo -e "${BOLD}Results saved to: $OUT_DIR/${NC}"
echo
for line in "${FINDINGS_SUMMARY[@]}"; do
    echo -e "  ${CYAN}*${NC} $line"
done
echo
echo -e "${BOLD}Files:${NC}"
find "$OUT_DIR" -maxdepth 1 -type f | while read -r f; do
    size=$(du -h "$f" | cut -f1)
    echo "  $size  $(basename $f)"
done
[[ -d "$OUT_DIR/sourcemaps" ]] && \
    echo "  $(du -sh "$OUT_DIR/sourcemaps" | cut -f1)  sourcemaps/"
echo
