# TDD plan: close the five "ship-first" detections

Scope: turn the five highest-confidence Obscura-detection rules an anti-bot
engineer would deploy first into failing tests, then land the minimum code
that flips each one green.

The five rules being addressed (from the adversarial analysis on branch
`claude/detect-stealth-browser-ww31f`):

1. **In-page** — `'webdriver' in navigator || typeof Deno !== 'undefined' ||
   Object.getOwnPropertyNames(window).some(k => /^_fp|_markNative|obscura/i.test(k))`
2. **In-page** — `Object.getOwnPropertyDescriptor(Element.prototype, 'classList') === undefined`
   (representative of ~100 missing prototype descriptors)
3. **In-page** — `canvas.toDataURL()` output is not a real PNG whose IHDR
   matches the canvas dimensions
4. **Edge** — JA4 / HTTP/2 SETTINGS deviation from a reference Chrome 145
   Linux profile for the claimed `User-Agent`
5. **Edge** — `Accept-CH` handshake completeness on the second request

Working branch: `claude/detect-stealth-browser-ww31f`.

Discipline per item: **Red** (write the test, confirm it fails on current
`main` with `--features stealth`) → **Green** (minimum fix) → **Verify**
(re-run the test plus `scripts/verify-stealth.sh` to confirm no regressions
elsewhere).

---

## Shared scaffolding (land before any fix)

**Test fixtures and harness**

- `tests/fixtures/detect/` — static HTML pages, one per detection, each
  containing a single `<script>` that writes a JSON result to
  `document.title`. The pattern is already used loosely by
  `scripts/verify-stealth.sh`; formalize it.
- `tests/detect_runner.rs` — workspace-level integration test that spins
  `obscura fetch --features stealth` against each fixture via a localhost
  HTTP server, parses the result title, and asserts PASS.
- `scripts/verify-stealth.sh` gets a new block at the top that runs the
  above test harness before invoking sannysoft / creepjs. If any
  `detect_runner` assertion fails, abort before the heavier
  cloud-dependent checks.

This gives one source of truth that the rules an adversary would ship are
neutralized end-to-end, not just in isolated unit tests.

---

## Rule 1 — `webdriver` / `Deno` / bootstrap-globals leak (in-page)

Single detection, three independent fixes. Do them as one commit because
they share the IIFE refactor.

### Red

`tests/fixtures/detect/globals.html`:

```html
<script>
  const leaks = Object.getOwnPropertyNames(window).filter(k =>
    /^_fp|^_mark|^_wrap|^_resolveUrl|^_registerIframe|obscura/i.test(k));
  document.title = JSON.stringify({
    webdriver_in_nav: 'webdriver' in navigator,
    deno_typeof: typeof Deno,
    bootstrap_leaks: leaks,
  });
</script>
```

Assertion in `detect_runner.rs`: `webdriver_in_nav === false &&
deno_typeof === 'undefined' && bootstrap_leaks.length === 0`.

Plus an inline Rust unit test in `crates/obscura-js/src/bootstrap_test.rs`
that evaluates those three expressions in a fresh V8 isolate (no page
script) — catches the pre-init race for `Deno`.

### Green

`crates/obscura-js/js/bootstrap.js`:

1. Wrap the entire bootstrap body (lines ~24..3340) in
   `(function(){ ... })();`. Anything the page actually needs (`fetch`,
   `XMLHttpRequest`, `navigator`, etc.) gets assigned onto `globalThis`
   explicitly inside the IIFE.
2. Move `delete globalThis.Deno` to the top of the IIFE, before any other
   statement — closes the pre-init window.
3. Remove the `'webdriver'` getter entirely. Real Chrome has no such
   property; replace with nothing.
4. Delete the post-hoc `defineProperty({enumerable:false})` loop at
   ~3333-3348 — dead once IIFE wrapping lands.

### Verify

Test flips green. Re-run `scripts/verify-stealth.sh` to confirm sannysoft
"WebDriver" and "WebDriver Advanced" both move to `passed`, and CreepJS
`Deno in windowKeys` flips false.

---

## Rule 2 — `Element.prototype` descriptor coverage (in-page)

### Red

`tests/fixtures/detect/element_descriptors.html`:

```html
<script>
  // Golden list committed alongside the fixture.
  const EXPECTED = ['innerHTML','outerHTML','classList','attributes','children',
    'clientWidth','clientHeight','offsetWidth','offsetHeight','scrollTop',
    'scrollLeft','scrollWidth','scrollHeight','dataset','id','className',
    'tagName','namespaceURI','slot','part','shadowRoot', /* ... */ ];
  const missing = EXPECTED.filter(n =>
    !Object.getOwnPropertyDescriptor(Element.prototype, n));
  document.title = JSON.stringify({ missing });
</script>
```

Assertion: `missing.length === 0`.

The golden list lives at `tests/fixtures/detect/element_prototype.json`,
generated once from a real Chrome 145 Linux. Document the regeneration
procedure in a README alongside the fixture; do not hand-curate.

### Green

`crates/obscura-js/js/bootstrap.js:768-780`: replace the hard-coded
15-name loop with a loop over the golden list (inlined as a JS array
constant via `include_str!` or a small `build.rs`). Each name gets
`{get, set, enumerable: true, configurable: true}`, where `get`/`set`
delegate to the existing attribute backing store.

For names with no backing store (`shadowRoot`, `slot`, etc.), the getter
returns a type-correct default (`null`, `""`, `0`) — still a real
descriptor, still satisfies the test.

### Verify

Test flips green. The "100+ Element.prototype failures" count in
`docs/bot-detection-audit.md` drops to near zero — update the audit doc
in the same PR.

---

## Rule 3 — Canvas `toDataURL()` returns a real PNG (in-page)

### Red

`tests/fixtures/detect/canvas_png.html`:

```html
<script>
(async () => {
  const c = document.createElement('canvas'); c.width = 220; c.height = 30;
  const ctx = c.getContext('2d'); ctx.fillText('x',0,0);
  const a = c.toDataURL(), b = c.toDataURL();
  const bin = atob(a.slice(a.indexOf(',')+1));
  const bytes = Uint8Array.from(bin, x => x.charCodeAt(0));
  const sig = [137,80,78,71,13,10,26,10].every((v,i) => bytes[i] === v);
  // IHDR at offset 16..24 (big-endian width, height)
  const w = (bytes[16]<<24)|(bytes[17]<<16)|(bytes[18]<<8)|bytes[19];
  const h = (bytes[20]<<24)|(bytes[21]<<16)|(bytes[22]<<8)|bytes[23];
  document.title = JSON.stringify({ sig, w, h, stable: a === b });
})();
</script>
```

Assertion: `sig === true && w === 220 && h === 30 && stable === true`.

Stability is preserved — determinism alone isn't the attack surface here;
*invalidity* is.

### Green

Two options:

- **Option A (preferred):** move canvas encoding to Rust. Add an
  `op_canvas_encode_png` op in `crates/obscura-js/src/ops/` that takes
  the pixel buffer (already in `_ctx._buf`) and returns a base64 PNG via
  the `png` crate. The JS shim at `bootstrap.js:2694-2711` calls the op
  instead of fabricating a base64 suffix.
- **Option B:** ship a minimal pure-JS PNG encoder (IHDR + IDAT with
  stored-mode deflate, CRC32, IEND). ~150 lines, no dependencies, but
  adds bootstrap weight.

Pick A unless there's a reason not to add an op.

### Verify

Test flips green. One-off: dump the result to `/tmp/out.png` and open it
— it should render whatever the script drew. Add an assertion that
`a.length > 200` to catch a regression to the synthetic-base64 shortcut.

---

## Rule 4 — JA4 / HTTP/2 SETTINGS match reference Chrome 145 Linux (edge)

This rule cannot be "fixed" by writing code inside Obscura — `wreq`
performs the actual handshake. What we can do is pin and snapshot, so
drift surfaces immediately.

### Red

`crates/obscura-net/tests/tls_fingerprint.rs`:

1. Spin up a local TLS listener using `rustls` with a self-signed cert.
   The listener doesn't speak HTTP — it captures the raw ClientHello
   bytes, derives JA4, then drops the connection.
2. Spin up a second listener that completes the TLS handshake, speaks
   HTTP/2, captures the first SETTINGS frame, and logs its values.
3. Run `obscura-net`'s stealth client against both, once each.
4. Assert captured JA4 equals the string committed at
   `crates/obscura-net/tests/fixtures/chrome145_linux.ja4` and the
   SETTINGS HashMap equals `chrome145_linux.h2settings.json`.

Fixtures are generated **once** by capturing real Chrome 145 Linux
against the same harness. Document the capture procedure inline in the
test file.

### Green

The first time this test runs on current `main`, it records the JA4
`wreq` produces and compares against the real-Chrome fixture:

- **If they match:** commit is green. The test now acts as a regression
  gate — any future `wreq` bump or `Cargo.lock` change that perturbs the
  fingerprint breaks CI loudly.
- **If they don't match:** file the delta, bump `wreq` to a newer RC if
  available, or open an upstream issue. No Obscura-side code change can
  fix a `wreq` bug; but the test prevents shipping a false sense of
  security.

No "minimal implementation" to write — the *test itself* is the
deliverable. Treat it as a supply-chain canary.

### Verify

Extend `.github/workflows/ci.yml` `stealth` job to run
`cargo test -p obscura-net --features stealth --test tls_fingerprint`.
Linux-only (matches the existing stealth-is-Linux-only gate).

---

## Rule 5 — `Accept-CH` handshake completeness (edge)

The biggest behavior change; save for last.

### Red

`crates/obscura-net/tests/accept_ch.rs`:

1. Spin up a local HTTP/2 server (using `hyper`) that:
   - On request 1: returns `200` with `Accept-CH: sec-ch-ua-platform-version,
     sec-ch-ua-arch, sec-ch-ua-bitness, sec-ch-ua-full-version-list,
     sec-ch-ua-model` and records the request headers.
   - On request 2: records the request headers and returns `200`.
2. Stealth client fetches the same URL twice in sequence.
3. Assertions on request 2's headers:
   - All five `sec-ch-ua-*` headers declared in `Accept-CH` are present.
   - Values are consistent with `STEALTH_USER_AGENT` and the values JS
     exposes via `navigator.userAgentData.getHighEntropyValues`
     (`bootstrap.js:1192-1214`): `sec-ch-ua-platform-version: "6.8.0"`,
     `sec-ch-ua-arch: "x86"`, `sec-ch-ua-bitness: "64"`,
     `sec-ch-ua-full-version-list` includes `"Google Chrome";v="145.0.0.0"`,
     `sec-ch-ua-model: ""`.
4. Second assertion: same client instance, fetch a *different* origin —
   high-entropy hints must **not** leak cross-origin (Chrome scopes
   `Accept-CH` per-origin).

### Green

Single source of truth for UA-CH values — extract the duplicated strings
in `wreq_client.rs:21` and `bootstrap.js:1192-1214` into a shared fixture
file `crates/obscura-net/data/client_hints.json`, loaded by both sides
(JS via `include_str!`, Rust via `serde_json`). Eliminates future drift.

In `crates/obscura-net/src/wreq_client.rs`:

1. Add `accept_ch_cache: Arc<RwLock<HashMap<Origin, HashSet<HeaderName>>>>`
   to the client.
2. After every response, parse `Accept-CH`; union into the cache for that
   origin.
3. Before every request, look up the origin in the cache; for each
   declared hint in `ClientHintsSupported`, insert the corresponding
   header with the value from `client_hints.json`.
4. Hints outside the low-entropy default three (`sec-ch-ua`,
   `sec-ch-ua-mobile`, `sec-ch-ua-platform`) are only added when
   declared.

Scope control: only support the subset of hints declared in our UA
profile. Do not implement `sec-ch-prefers-*` — not needed to defeat the
detection.

### Verify

Test flips green. Extend `tls_fingerprint.rs` logic to also record
request headers and assert order matches Chrome 145 Linux (UA before
`sec-ch-ua-*` before `sec-fetch-*` before `accept-*`), since header
order is a weaker but real signal.

---

## Summary sequencing

| # | Rule                                       | Tier    | Blast radius              | Effort |
|---|--------------------------------------------|---------|---------------------------|--------|
| 1 | Globals leak (IIFE + webdriver + Deno)     | in-page | bootstrap-wide refactor   | M      |
| 2 | Element.prototype descriptors              | in-page | targeted                  | S      |
| 3 | Canvas real PNG                            | in-page | new op                    | M      |
| 4 | JA4 / H2 SETTINGS snapshot                 | edge    | new test only             | S      |
| 5 | Accept-CH state machine                    | edge    | new client behavior       | L      |

Land 4 first (snapshot before changing anything, so we can tell if any
later change perturbs the handshake). Then 2, 3, 1, 5 — small to large,
behavior-preserving to behavior-changing.

**Risk to flag before starting:** Rule 1's IIFE refactor is the
riskiest single change. Any existing code that relies on a `var` /
`function` inside bootstrap being a window property will break. Plan a
full `scripts/verify-stealth.sh` run plus sannysoft and creepjs sweep as
the acceptance gate for that one commit alone, not bundled with the
others.
