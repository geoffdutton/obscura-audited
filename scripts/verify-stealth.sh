#!/usr/bin/env bash
# verify-stealth.sh — Run bot-detection checks against sannysoft and creepjs
# and report pass/fail for each signal.
#
# Usage:
#   ./scripts/verify-stealth.sh [--binary PATH] [--no-build] [--json]
#
# Options:
#   --binary PATH   Path to obscura binary (default: ./target/release/obscura)
#   --no-build      Skip cargo build step
#   --json          Emit machine-readable JSON summary to stdout (human report goes to stderr)

set -euo pipefail

# ── defaults ──────────────────────────────────────────────────────────────────
BINARY="./target/release/obscura"
BUILD=true
JSON_MODE=false
TIMEOUT=45

# Preserve original args so the Docker hint below can echo them back verbatim.
ORIG_ARGS=("$@")

# ── arg parse ─────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)   BINARY="$2"; shift 2 ;;
    --no-build) BUILD=false;  shift   ;;
    --json)     JSON_MODE=true; shift ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# ── platform guard ────────────────────────────────────────────────────────────
# `--features stealth` pulls in wreq → boring-sys2, whose `prefix-symbols`
# feature is broken on macOS/Windows (C-side rename is skipped but the Rust
# bindgen rename is applied, producing unresolved linker symbols). Run via
# Docker on non-Linux hosts — the Linux-ELF binary also can't execute on
# macOS, so the whole script must run inside the container.
if [[ "$(uname -s)" != "Linux" ]]; then
  cat >&2 <<EOF
verify-stealth.sh requires Linux (boring-sys2 prefix-symbols is macOS/Windows-broken).

Run via Docker:

  docker run --rm \\
    -v "\$PWD":/src -w /src \\
    -v obscura-cargo-registry:/usr/local/cargo/registry \\
    -v obscura-linux-target:/src/target \\
    rust:1.95 bash scripts/verify-stealth.sh ${ORIG_ARGS[*]:-}

The named volumes cache cargo's registry and the Linux target dir across
runs (the Linux target stays isolated from your macOS ./target). First run
is ~5 min (V8 compiles from source); subsequent runs are fast.
EOF
  exit 1
fi

# ── helpers ───────────────────────────────────────────────────────────────────
PASS=0; WARN=0; FAIL=0
RESULTS=()   # "status|name|value" triples

record() {            # record STATUS NAME VALUE
  local s="$1" n="$2" v="$3"
  RESULTS+=("$s|$n|$v")
  case "$s" in
    PASS) PASS=$((PASS+1)) ;;
    WARN) WARN=$((WARN+1)) ;;
    FAIL) FAIL=$((FAIL+1)) ;;
  esac
}

run_eval() {          # run_eval JS_EXPR  →  stdout = result, strips ERROR logs
  timeout "$TIMEOUT" "$BINARY" fetch "$CURRENT_URL" \
    --stealth --quiet --eval "$1" 2>/dev/null || true
}

section() { echo "" >&2; echo "── $1 ──" >&2; }
log()     { echo "  $1" >&2; }

# ── build ─────────────────────────────────────────────────────────────────────
if $BUILD; then
  echo "Building obscura (release, --features stealth)…" >&2
  cargo build --release --features stealth --quiet 2>&1 | tail -5 >&2
fi

if [[ ! -x "$BINARY" ]]; then
  echo "ERROR: binary not found at $BINARY" >&2
  exit 1
fi

echo "Binary: $BINARY  ($(du -sh "$BINARY" 2>/dev/null | cut -f1))" >&2
echo "Date:   $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >&2

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — Core navigator / window signals
# ══════════════════════════════════════════════════════════════════════════════
section "Core navigator / window signals"

CURRENT_URL="https://abrahamjuliot.github.io/creepjs/"

# webdriver in navigator
val=$(run_eval "'webdriver' in navigator")
if [[ "$val" == "false" ]]; then
  record PASS "webdriver-in-navigator" "$val"
  log "PASS  'webdriver' in navigator = false"
else
  record FAIL "webdriver-in-navigator" "$val"
  log "FAIL  'webdriver' in navigator = $val  (should be false)"
fi

# navigator.webdriver value
val=$(run_eval "String(navigator.webdriver)")
if [[ "$val" == "undefined" ]]; then
  record PASS "navigator.webdriver-value" "$val"
  log "PASS  navigator.webdriver = undefined"
else
  record FAIL "navigator.webdriver-value" "$val"
  log "FAIL  navigator.webdriver = $val  (should be undefined)"
fi

# window.Deno exposed
val=$(run_eval "typeof Deno")
if [[ "$val" == "undefined" ]]; then
  record PASS "window-Deno-hidden" "$val"
  log "PASS  typeof Deno = undefined"
else
  record FAIL "window-Deno-hidden" "$val"
  log "FAIL  typeof Deno = $val  (Deno runtime leaks into page scope)"
fi

# Internal __obscura_* globals
val=$(run_eval "Object.keys(window).filter(k=>k.startsWith('__obscura')||k.startsWith('_fp')||k==='_markNative'||k==='_dom').join(',')")
if [[ -z "$val" || "$val" == "null" ]]; then
  record PASS "internal-globals-hidden" "(none)"
  log "PASS  No internal bootstrap globals in Object.keys(window)"
else
  record FAIL "internal-globals-hidden" "$val"
  log "FAIL  Internal globals visible: $val"
fi

# HeadlessChrome in UA
val=$(run_eval "navigator.userAgent")
if echo "$val" | grep -q "HeadlessChrome"; then
  record FAIL "ua-no-headless" "$val"
  log "FAIL  UA contains 'HeadlessChrome'"
else
  record PASS "ua-no-headless" "${val:0:80}"
  log "PASS  UA looks clean: ${val:0:80}"
fi

# navigator.plugins type
val=$(run_eval "Object.prototype.toString.call(navigator.plugins)")
if [[ "$val" == "[object PluginArray]" ]]; then
  record PASS "plugins-type" "$val"
  log "PASS  navigator.plugins is PluginArray"
else
  record FAIL "plugins-type" "$val"
  log "FAIL  navigator.plugins toString = $val  (want [object PluginArray])"
fi

# navigator.plugins length
val=$(run_eval "navigator.plugins.length")
if [[ "$val" =~ ^[1-9][0-9]*(\.[0-9]+)?$ ]]; then
  record PASS "plugins-length" "$val"
  log "PASS  navigator.plugins.length = $val"
else
  record FAIL "plugins-length" "$val"
  log "FAIL  navigator.plugins.length = $val  (want > 0)"
fi

# navigator.languages
val=$(run_eval "Array.isArray(navigator.languages) && navigator.languages.length > 0")
if [[ "$val" == "true" ]]; then
  record PASS "navigator-languages" "$(run_eval "navigator.languages.join(',')")"
  log "PASS  navigator.languages populated"
else
  record FAIL "navigator-languages" "$val"
  log "FAIL  navigator.languages missing or empty"
fi

# window.chrome shape
val=$(run_eval "typeof window.chrome === 'object' && !!window.chrome.runtime")
if [[ "$val" == "true" ]]; then
  record PASS "chrome-object" "present"
  log "PASS  window.chrome.runtime present"
else
  record FAIL "chrome-object" "$val"
  log "FAIL  window.chrome or chrome.runtime missing"
fi

# Element.prototype descriptors
val=$(run_eval "typeof Object.getOwnPropertyDescriptor(Element.prototype,'innerHTML')")
if [[ "$val" == "object" ]]; then
  record PASS "element-proto-descriptors" "present"
  log "PASS  Element.prototype.innerHTML has descriptor"
else
  record FAIL "element-proto-descriptors" "$val"
  log "FAIL  Element.prototype.innerHTML descriptor = $val  (want object)"
fi

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — API completeness
# ══════════════════════════════════════════════════════════════════════════════
section "API completeness"

# Canvas2D _parseColor — gradient/pattern style crash
val=$(run_eval "
(function(){
  try {
    var c=document.createElement('canvas'); c.width=100; c.height=100;
    var ctx=c.getContext('2d');
    var g=ctx.createLinearGradient(0,0,100,0);
    g.addColorStop(0,'red'); g.addColorStop(1,'blue');
    ctx.fillStyle=g;
    ctx.fillRect(0,0,100,100);
    ctx.fillText('test',10,10);
    return 'ok';
  } catch(e) { return 'ERROR:'+e.message; }
})()")
if [[ "$val" == "ok" ]]; then
  record PASS "canvas-gradient-fillText" "ok"
  log "PASS  Canvas fillText with CanvasGradient style"
else
  record FAIL "canvas-gradient-fillText" "$val"
  log "FAIL  Canvas gradient fillText: $val"
fi

# AudioContext sampleRate
val=$(run_eval "
(function(){
  try { var ac=new AudioContext(); return String(ac.sampleRate); }
  catch(e) { return 'ERROR:'+e.message; }
})()")
if [[ "$val" =~ ^[0-9]+$ ]]; then
  record PASS "audiocontext-sampleRate" "$val Hz"
  log "PASS  AudioContext.sampleRate = $val"
else
  record FAIL "audiocontext-sampleRate" "$val"
  log "FAIL  AudioContext.sampleRate: $val"
fi

# AudioContext addEventListener
val=$(run_eval "
(function(){
  try { var ac=new AudioContext(); return typeof ac.addEventListener; }
  catch(e) { return 'ERROR:'+e.message; }
})()")
if [[ "$val" == "function" ]]; then
  record PASS "audiocontext-addEventListener" "function"
  log "PASS  AudioContext.addEventListener is function"
else
  record FAIL "audiocontext-addEventListener" "$val"
  log "FAIL  AudioContext.addEventListener = $val  (want function)"
fi

# OfflineAudioContext sampleRate
val=$(run_eval "
(function(){
  try { var oac=new OfflineAudioContext(1,44100,44100); return String(oac.sampleRate); }
  catch(e) { return 'ERROR:'+e.message; }
})()")
if [[ "$val" =~ ^[0-9]+$ ]]; then
  record PASS "offline-audiocontext-sampleRate" "$val Hz"
  log "PASS  OfflineAudioContext.sampleRate = $val"
else
  record FAIL "offline-audiocontext-sampleRate" "$val"
  log "FAIL  OfflineAudioContext.sampleRate: $val"
fi

# SVG getBBox
val=$(run_eval "
(function(){
  try {
    var s=document.createElementNS('http://www.w3.org/2000/svg','svg');
    document.body.appendChild(s);
    var r=s.getBBox();
    return 'ok';
  } catch(e) { return 'ERROR:'+e.message; }
})()")
if [[ "$val" == "ok" ]]; then
  record PASS "svg-getBBox" "ok"
  log "PASS  SVGSVGElement.getBBox() implemented"
else
  record FAIL "svg-getBBox" "$val"
  log "FAIL  SVG getBBox: $val"
fi

# FontFace
val=$(run_eval "typeof FontFace")
if [[ "$val" == "function" ]]; then
  record PASS "FontFace-defined" "function"
  log "PASS  FontFace is defined"
else
  record FAIL "FontFace-defined" "$val"
  log "FAIL  FontFace = $val  (want function)"
fi

# iframe.contentDocument
val=$(run_eval "
(function(){
  try {
    var f=document.createElement('iframe');
    document.body.appendChild(f);
    return typeof f.contentDocument;
  } catch(e) { return 'ERROR:'+e.message; }
})()")
if [[ "$val" == "object" ]]; then
  record PASS "iframe-contentDocument" "object"
  log "PASS  iframe.contentDocument accessible"
else
  record FAIL "iframe-contentDocument" "$val"
  log "FAIL  iframe.contentDocument = $val  (want object)"
fi

# WebGL VERSION string
val=$(run_eval "
(function(){
  try {
    var c=document.createElement('canvas');
    var gl=c.getContext('webgl');
    if(!gl) return 'no-context';
    var v=gl.getParameter(gl.VERSION);
    return typeof v === 'string' && v.length > 0 ? v : 'got:'+JSON.stringify(v);
  } catch(e) { return 'ERROR:'+e.message; }
})()")
if echo "$val" | grep -qi "webgl\|opengl"; then
  record PASS "webgl-version-string" "${val:0:60}"
  log "PASS  WebGL VERSION = ${val:0:60}"
else
  record FAIL "webgl-version-string" "$val"
  log "FAIL  WebGL getParameter(VERSION) = $val  (want version string)"
fi

# WebGL uniform2f
val=$(run_eval "
(function(){
  try {
    var c=document.createElement('canvas');
    var gl=c.getContext('webgl');
    if(!gl) return 'no-context';
    return typeof gl.uniform2f;
  } catch(e) { return 'ERROR:'+e.message; }
})()")
if [[ "$val" == "function" ]]; then
  record PASS "webgl-uniform2f" "function"
  log "PASS  gl.uniform2f is function"
else
  record FAIL "webgl-uniform2f" "$val"
  log "FAIL  gl.uniform2f = $val  (want function)"
fi

# getClientRects count
val=$(run_eval "
(function(){
  try {
    var d=document.createElement('div');
    d.style.width='50px';
    d.innerHTML='<span>'+('word ').repeat(20)+'</span>';
    document.body.appendChild(d);
    return d.querySelector('span').getClientRects().length;
  } catch(e) { return 'ERROR:'+e.message; }
})()")
int_val="${val%.*}"  # strip trailing .0
if [[ "$int_val" =~ ^[0-9]+$ ]] && [[ "$int_val" -ge 2 ]] 2>/dev/null; then
  record PASS "getClientRects-count" "$val rects"
  log "PASS  getClientRects() returned $val rects"
elif [[ "$int_val" == "1" ]]; then
  record WARN "getClientRects-count" "$val rect (want ≥2 for wrapped text)"
  log "WARN  getClientRects() returned only $val rect (want ≥2 for wrapped text)"
else
  record FAIL "getClientRects-count" "$val"
  log "FAIL  getClientRects(): $val"
fi

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — CreepJS totalLies  (live fetch, network required)
# ══════════════════════════════════════════════════════════════════════════════
section "CreepJS (abrahamjuliot.github.io/creepjs)"

CURRENT_URL="https://abrahamjuliot.github.io/creepjs/"
lies_val=$(run_eval "window.Fingerprint?.lies?.totalLies ?? 'unavailable'")
deno_in_win=$(run_eval "window.Fingerprint?.windowFeatures?.keys?.includes('Deno') ?? 'unavailable'")

lies_int="${lies_val%.*}"  # strip trailing .0
if [[ "$lies_int" =~ ^[0-9]+$ ]]; then
  if [[ "$lies_int" -eq 0 ]]; then
    record PASS "creepjs-totalLies" "0"
    log "PASS  totalLies = 0"
  elif [[ "$lies_int" -lt 20 ]]; then
    record WARN "creepjs-totalLies" "$lies_val"
    log "WARN  totalLies = $lies_val  (low, but > 0)"
  else
    record FAIL "creepjs-totalLies" "$lies_val"
    log "FAIL  totalLies = $lies_val  (high — will be flagged)"
  fi
else
  record WARN "creepjs-totalLies" "$lies_val"
  log "WARN  totalLies unavailable (async fingerprint may not have resolved)"
fi

if [[ "$deno_in_win" == "false" ]]; then
  record PASS "creepjs-deno-in-windowFeatures" "false"
  log "PASS  Deno not in creepjs windowFeatures"
elif [[ "$deno_in_win" == "true" ]]; then
  record FAIL "creepjs-deno-in-windowFeatures" "true"
  log "FAIL  Deno detected in creepjs windowFeatures"
else
  record WARN "creepjs-deno-in-windowFeatures" "$deno_in_win"
  log "WARN  creepjs Deno check: $deno_in_win"
fi

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — Sannysoft  (live fetch, network required)
# ══════════════════════════════════════════════════════════════════════════════
section "Sannysoft (bot.sannysoft.com)"

CURRENT_URL="https://bot.sannysoft.com/"

sanny_ua=$(run_eval "document.getElementById('user-agent-result')?.className ?? 'missing'")
sanny_wd=$(run_eval "document.getElementById('webdriver-result')?.className ?? 'missing'")
sanny_adv=$(run_eval "document.getElementById('advanced-webdriver-result')?.className ?? 'missing'")
sanny_chrome=$(run_eval "document.getElementById('chrome-result')?.className ?? 'missing'")
sanny_wd_val=$(run_eval "document.getElementById('webdriver-result')?.textContent?.trim() ?? ''")
sanny_chrome_val=$(run_eval "document.getElementById('chrome-result')?.textContent?.trim() ?? ''")

check_sanny() {   # check_sanny NAME CLASSVAL DISPLAY_VAL
  local name="$1" cls="$2" disp="$3"
  if echo "$cls" | grep -q "passed"; then
    record PASS "sannysoft-$name" "$disp"
    log "PASS  sannysoft $name"
  elif [[ "$cls" == "missing" ]]; then
    record WARN "sannysoft-$name" "element not found (page may not have loaded)"
    log "WARN  sannysoft $name — element not found"
  else
    record FAIL "sannysoft-$name" "$disp"
    log "FAIL  sannysoft $name: $disp"
  fi
}

check_sanny "user-agent"         "$sanny_ua"     ""
check_sanny "webdriver"          "$sanny_wd"     "$sanny_wd_val"
check_sanny "webdriver-advanced" "$sanny_adv"    ""
check_sanny "chrome-object"      "$sanny_chrome" "$sanny_chrome_val"

# ══════════════════════════════════════════════════════════════════════════════
#  REPORT
# ══════════════════════════════════════════════════════════════════════════════
TOTAL=$((PASS + WARN + FAIL))

echo "" >&2
echo "══════════════════════════════════════════" >&2
echo "  Results: $PASS/$TOTAL passed  |  $WARN warn  |  $FAIL failed" >&2
echo "══════════════════════════════════════════" >&2

if $JSON_MODE; then
  TMP_RESULTS=$(mktemp)
  for entry in "${RESULTS[@]:-}"; do
    echo "$entry" >> "$TMP_RESULTS"
  done
  python3 - "$TMP_RESULTS" "$PASS" "$WARN" "$FAIL" "$TOTAL" <<'PYEOF'
import json, sys
results = []
with open(sys.argv[1]) as f:
    for line in f:
        parts = line.rstrip('\n').split('|', 2)
        if len(parts) == 3:
            results.append({"status": parts[0], "name": parts[1], "value": parts[2]})
print(json.dumps({
    "pass": int(sys.argv[2]), "warn": int(sys.argv[3]),
    "fail": int(sys.argv[4]), "total": int(sys.argv[5]),
    "results": results
}, indent=2))
PYEOF
  rm -f "$TMP_RESULTS"
fi

# Exit non-zero if any failures
[[ $FAIL -eq 0 ]]
