# Obscura security & trust audit

**Audit date:** 2026-04-23
**Commit audited:** `b00a1f2` (tip of `main`)
**Upstream:** `github.com/h4ckf0r0day/obscura` (created 2026-04-13, 10 days old at audit time)
**Scope:** full source tree — 6 crates, ~12 kLOC Rust + ~3 kLOC bundled JS
**Out of scope:** contents of the pre-built release tarballs on GitHub Releases (see §3)

---

## TL;DR

The **source** is materially tamer than the surface signals suggest. It is a real headless-browser project doing what the README claims, with surprisingly strong baseline hardening (SSRF filter, localhost-only bind, in-memory state, tight JS↔Rust op surface). No beacons, no exfil, no update-channel, no env-var reads, no disk persistence, no hidden listeners, no obfuscated payloads, no shell execution surface exposed to rendered JS, no `danger_accept_invalid_certs`, no `unsafe` outside three legitimate html5ever interop lines.

The **distribution layer** is the real problem. The pre-built tarballs are not cryptographically bound to this source: no signatures, no SHA256SUMS, no SLSA provenance, tag-pinned (not SHA-pinned) actions, and a `continue-on-error: true` on the stealth build step that lets a stealth-featured release silently diverge from the default build. Combined with the author's pseudonymous handle, the 10-day-old repo, and the anomalously high star velocity (1,681 stars / 123 forks in 10 days), the releases should be treated as unsigned third-party binaries from an unvetted author.

**Bottom line:** build from source. Do not `curl | tar x` the releases.

---

## 1. Trust signals (non-code)

| Signal | Value | Read |
|---|---|---|
| Author handle | `h4ckf0r0day` ("hack for 0-day") | Intentional, non-neutral. Not proof of malice; is a choice. |
| Repo creation | 2026-04-13 | 10 days old at audit. |
| Commits | 5 total | "Initial Release" + three README/workflow tweaks. |
| Contributors | 1 | No second reviewer. |
| Stars / forks | 1,681 / 123 (at audit) | Extremely high velocity for an anon 10-day-old repo. Either astroturfed or HN/PR spike. |
| Subscribers / issues | 10 / 14 | Low engagement relative to stars — classic astroturf shape. |
| Version | `0.1.0` | No track record. |
| License | README: Apache 2.0. LICENSE file: Apache 2.0 text. `Cargo.toml`: `license = "MIT"` | **Mismatch**. Sloppy. |

None of these prove anything. They establish that the operator is unvetted and that conventional OSS trust signals (stars, age, contributor count) either don't exist or are unreliable for this repo.

---

## 2. Codebase map

| Crate | LoC | Responsibility | Notable deps |
|---|---:|---|---|
| `obscura-dom` | ~1.8 k | Servo-derived DOM (html5ever, markup5ever, selectors) | `html5ever 0.29`, `selectors 0.26` |
| `obscura-net` | ~1.2 k | HTTP client (reqwest + optional `wreq` for TLS-fingerprint spoofing), cookie jar, tracker blocklist, robots.txt | `reqwest 0.12`, `wreq 6.0.0-rc.28` (stealth), `wreq-util 3.0.0-rc.10` (stealth) |
| `obscura-js` | ~5.0 k | V8 runtime via `deno_core`; `bootstrap.js` provides navigator/document/fetch/XHR/Worker shims and anti-fingerprint overrides; 8 `op_*` host functions | `deno_core 0.350`, `deno_error 0.6` |
| `obscura-browser` | ~1.0 k | Page/BrowserContext orchestration glue | workspace deps |
| `obscura-cdp` | ~2.2 k | Chrome DevTools Protocol server (Target/Page/Runtime/DOM/Network/Fetch/Storage/Input/LP) over WebSocket | `tokio-tungstenite 0.26` |
| `obscura-cli` | ~0.7 k | `obscura` + `obscura-worker` binaries, subcommands: `serve`, `fetch`, `scrape`; multi-worker TCP load balancer for parallel scraping | `clap 4` |

---

## 3. Release / supply chain

### 3.1 Release workflow (`.github/workflows/release.yml`)

```yaml
- uses: actions/checkout@v4
- uses: dtolnay/rust-toolchain@stable
- name: Build
  run: cargo build --release --target ${{ matrix.target }}
- name: Build stealth
  run: cargo build --release --target ${{ matrix.target }} --features stealth
  continue-on-error: true          # ← red flag
- uses: softprops/action-gh-release@v2
  with:
    files: |
      ${{ matrix.name }}.tar.gz
      ${{ matrix.name }}.zip
```

**Findings:**

| # | Issue | Severity |
|---|---|---|
| R1 | No SHA256SUMS file published with releases | High |
| R2 | No cosign / sigstore signing | High |
| R3 | No SLSA provenance / `--attestations` | Medium |
| R4 | No reproducible-build documentation | Medium |
| R5 | `continue-on-error: true` on the stealth build lets a release succeed even if the stealth binary doesn't match the non-stealth one — stealth artifact can silently diverge | Medium |
| R6 | Actions pinned by tag, not commit SHA (`actions/checkout@v4`, `dtolnay/rust-toolchain@stable`, `softprops/action-gh-release@v2`) — tags can be force-moved by the action maintainer | Medium |
| R7 | Matrix covers Linux/macOS/Windows but only the "Build" step produces the default artifact; a compromised runner or action could swap the tarball before upload without detection | Medium |

**Read:** the workflow builds from the same source you can read, but there is no mechanism to prove that the binary you `curl`ed is the output of this workflow for this commit. Treat the tarballs as unsigned third-party binaries.

### 3.2 Dependencies

- **Sources:** every entry in `Cargo.lock` resolves to `registry+https://github.com/rust-lang/crates.io-index`. No git deps, no path-remapping of registry crates, no `[patch.crates-io]`.
- **Checksums:** present for all registry crates.
- **Transitive count:** ~359 crates (normal for deno_core + reqwest + html5ever).
- **proc-macros:** ~39 occurrences in lock file — consistent with ecosystem norms (serde_derive, tokio_macros, clap_derive, etc.). No unfamiliar / recently-created proc-macro crates.
- **Risk pins worth flagging:**
  - `wreq 6.0.0-rc.28`, `wreq-util 3.0.0-rc.10` — both **release candidates**. The `rquest` / `reqwest-impersonate` / `wreq` ecosystem has seen maintainer-handoff churn and typosquat pressure historically. Their purpose is TLS-handshake impersonation (JA3/JA4 spoofing). If you build without `--features stealth`, neither is compiled in.
  - `deno_core 0.350` / `deno_error 0.6.1` — current, mainline Deno.

---

## 4. Runtime security posture

### 4.1 Network attack surface (from outside the process)

- CDP server binds to **127.0.0.1 only** (`crates/obscura-cli/src/main.rs:199`, `crates/obscura-cdp/src/server.rs:32-34`). Not exposed to LAN.
- Multi-worker load balancer (`main.rs:203-238`) listens on `127.0.0.1:{port}` and forwards to `127.0.0.1:{port+N}`. 4-byte `peek()` inspection is fine for localhost but would be trivially fooled if ever exposed publicly — don't expose it.
- No other listeners. No hidden UDP, no second HTTP port, no WebRTC.

### 4.2 SSRF / URL validation

**`op_fetch_url`** (`crates/obscura-js/src/ops.rs:552-601`) actively validates every URL before network IO:

```rust
fn validate_fetch_url(url: &url::Url) -> Result<(), String> {
    // scheme must be http or https
    // Ipv4: rejects loopback, private, link-local, broadcast, documentation
    // Ipv6: rejects loopback, unicast_link_local
    // Domain: rejects "localhost", "*.localhost", "127.0.0.1", "::1"
}
```

Same filter in `crates/obscura-net/src/client.rs:67-116` for the native HTTP path. This is a **positive** finding — most scraping stacks don't filter here and are usable as internal-network probes when pointed at hostile pages.

**Gap:** `ObscuraModuleLoader::load` (`crates/obscura-js/src/module_loader.rs:47-92`) fetches ES modules over HTTP with **no such validation**. A rendered page can do:

```js
await import('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
```

…and the module loader will fetch and (attempt to) execute it. This is a real SSRF vector if you ever run this headless browser against hostile pages in a cloud environment.

### 4.3 JS↔Rust bridge

Only **8 ops** are exposed to the V8 runtime (`crates/obscura-js/src/ops.rs`):

| op | Capability |
|---|---|
| `op_dom` | DOM CRUD against the host-side tree |
| `op_console_msg` | Write to tracing logs |
| `op_fetch_url` | HTTP fetch (SSRF-filtered, CORS-enforced) |
| `op_get_cookies` / `op_set_cookie` | Cookie jar access |
| `op_navigate` | Set `pending_navigation` for top-level nav |
| `op_log_intercept_request` / `op_fetch_intercept_response` (build-extension) | CDP Fetch-domain interception plumbing |

**Not exposed to JS:** filesystem, process spawn, environment variables, shell, clipboard, file pickers, USB, Bluetooth, native dialogs, anything OS-level. JS running in a rendered page cannot escape to the host beyond these 8 ops.

### 4.4 Filesystem / environment

Runtime grep (`crates/obscura-*/src/**.rs`, excluding `build.rs`):

- `std::env::var`: **0 calls** at runtime (only `OUT_DIR` in `build.rs`).
- `std::fs::write` / `File::create` / `OpenOptions`: **0 calls** at runtime (only the V8 snapshot write in `build.rs`).
- `Command::new` / process spawn: only the CLI spawning sibling `obscura-worker` and worker children (`main.rs:181,192,442`) — legitimate.
- Home / XDG / `dotfiles`: **0 references**.
- Cookie jar (`crates/obscura-net/src/cookies.rs`): in-memory only; no disk persistence.

**Read:** the running binary does not read your env, does not write to your home directory, does not touch files outside the process. State is ephemeral.

### 4.5 TLS

- `reqwest` client: `danger_accept_invalid_certs(false)` explicitly set (`crates/obscura-net/src/client.rs:164`). No `accept_invalid_hostnames`. No custom cert stores outside `wreq` using system CA roots.
- `native-tls-vendored` feature on reqwest: bundles a vendored OpenSSL so the binary is self-contained. Means it does **not** use the system TLS stack — both a hardening property (binary is static) and a fingerprinting property (TLS handshake looks the same everywhere).
- `wreq` stealth client: intentionally emulates Chrome 145's TLS handshake via `Emulation::Chrome145` — see §5.

### 4.6 `unsafe` / FFI

`grep -rE 'unsafe[[:space:]]*\{|unsafe fn'`:

```
crates/obscura-dom/src/tree_sink.rs:18:  let name = unsafe { &*self.name };
crates/obscura-dom/src/tree_sink.rs:25:  unsafe { &(*self.name).ns }
crates/obscura-dom/src/tree_sink.rs:29:  unsafe { &(*self.name).local }
```

All three are inside `ObscuraElemName`, implementing html5ever's `ElemName` trait. The trait requires returning borrows whose lifetime is tied to a `Ref<'a, ()>` guard held in the same struct — the pattern is standard for Servo's `RefCell`-based trees. Low risk. No FFI elsewhere.

### 4.7 Build scripts / proc-macros

- One in-tree `build.rs`: `crates/obscura-js/build.rs`. It runs `deno_core::snapshot::create_snapshot` on the bundled `bootstrap.js` and writes a V8 snapshot to `OUT_DIR`. No network, no shell, no external file reads beyond `include_str!("js/bootstrap.js")`. Safe.
- ~39 proc-macro occurrences in `Cargo.lock`, all in mainstream ecosystem crates (`serde_derive`, `tokio-macros`, `clap_derive`, `thiserror-impl`, `async-trait`, etc.). No unfamiliar proc-macros.

### 4.8 Hidden URLs / telemetry / beacons

Grep for any URL outside test/example/standards-body domains: **zero hits**. The only URLs in source are `example.com`, `other.com`, `news.ycombinator.com`, `quotes.toscrape.com`, `wikipedia.org`, `github.com/h4ckf0r0day/obscura` (README), and standards-body refs. No hardcoded C2, no update channel, no phone-home.

---

## 5. Stealth / anti-detection features

Explicit, documented, and extensive. Two layers.

### 5.1 JS layer (`crates/obscura-js/js/bootstrap.js`, always compiled in)

| Mechanism | Line | Purpose |
|---|---:|---|
| `navigator.webdriver = undefined` | 1017 | Defeat the canonical headless check |
| `Function.prototype.toString` patched to return `[native code]` for tracked fns | 30-39 | Defeat sniffers that check whether an API is a monkey-patch |
| `_fpRand` + per-session GPU / screen / canvas / audio / battery fingerprint | 60-115 | Randomize fingerprints per session |
| Fake `navigator.plugins` (PDF viewers) and `mimeTypes` | 1019-1040 | Headful-browser shape |
| `navigator.userAgentData.getHighEntropyValues` returning Chrome 145 UA-CH | 1041-1063 | UA-Client-Hints spoofing |
| `chrome.*` shim (app / runtime / csi / loadTimes) | 1089-1094 | Defeat `typeof chrome !== 'undefined'` checks |
| Canvas `getContext` / `toDataURL` / `toBlob` stubs | 2296-2363 | Canvas fingerprint spoofing |
| `AnalyserNode.getByteFrequencyData` / `getFloatFrequencyData` with randomized noise | 2432-2433 | AudioContext fingerprint spoofing |
| `Intl.DateTimeFormat.prototype.resolvedOptions` override | 2513-2524 | Locale fingerprint control |
| `Error.prototype.stack` cached getter (configurable:false) | 50-59 | Defeat stack-trace detection that introspects call sites |
| `event.isTrusted = true` for dispatched events | 1747 | Defeat `isTrusted`-based CAPTCHA gates |

**Read:** this is specifically targeted at the WAF fingerprinting stack — Cloudflare, DataDome, PerimeterX, Akamai Bot Manager, Kasada. Each of the items above matches a well-known bypass for those products.

### 5.2 TLS layer (`crates/obscura-net/src/wreq_client.rs`, `--features stealth` only)

```rust
let emulation_opts = wreq_util::EmulationOption::builder()
    .emulation(wreq_util::Emulation::Chrome145)
    .emulation_os(wreq_util::EmulationOS::Linux)
    .build();
```

`wreq` replaces reqwest's default TLS handshake with one that mimics Chrome 145 byte-for-byte at the JA3/JA4 level. This is the only reason `wreq` / `wreq-util` exist; they are not general-purpose HTTP clients.

### 5.3 Tracker / ad blocklist

`crates/obscura-net/src/pgl_domains.txt` — 3,520 domains. Appears to be Peter Lowe's list (PGL — hence the filename) verbatim. Not a red flag in itself; same list shipped by uBlock Origin, Pi-hole defaults, etc. Tests assert `google-analytics.com`, `doubleclick.net`, `adnxs.com`, `criteo.com` match.

### 5.4 Dual-use assessment

The feature set is specifically purpose-built to defeat bot-detection systems on third-party sites. Legitimate uses exist (QA on your own site, scraping sites you own, agent testing), but:

- Using it against sites that have deployed the above WAFs without consent is adversarial; some combinations are CFAA-adjacent in the US depending on ToS and whether the site took "technical measures" to exclude you (WAF ≈ yes).
- **This is a legal / policy question, not a code question.** The code is not inherently malicious; its application can be.

---

## 6. Findings summary

| # | Finding | Severity | Location |
|---|---|---|---|
| F1 | Pre-built release tarballs lack signatures, checksums, provenance | **High** (distribution) | `.github/workflows/release.yml` |
| F2 | `continue-on-error: true` on stealth build lets artifact silently diverge | Medium | `.github/workflows/release.yml:41` |
| F3 | GitHub Actions pinned by tag, not commit SHA | Medium | `.github/workflows/release.yml:30-58` |
| F4 | Author is pseudonymous (`h4ckf0r0day`) with 10-day-old repo and anomalous star velocity | Signal | upstream metadata |
| F5 | `ObscuraModuleLoader::load` fetches ES modules without SSRF filter — bypasses the filter that guards `op_fetch_url` | **Medium** (runtime, with hostile-page threat) | `crates/obscura-js/src/module_loader.rs:47-92` |
| F6 | License declaration mismatch (`Cargo.toml` = MIT; LICENSE + README = Apache 2.0) | Low | `Cargo.toml:15` |
| F7 | Stealth dependencies (`wreq`, `wreq-util`) are release candidates from an ecosystem with typosquat / handoff history | Low | `crates/obscura-net/Cargo.toml` |
| F8 | README benchmarks unverifiable (no reproducer, no methodology) | Low / non-security | `README.md` |
| F9 | Multi-worker load balancer does raw TCP forwarding with 4-byte peek; safe on 127.0.0.1, unsafe if ever exposed | Low | `crates/obscura-cli/src/main.rs:203-238` |
| F10 | `Worker` shim uses `new Function(...)` to execute worker code | Low (by-design) | `crates/obscura-js/js/bootstrap.js:2582` |
| F11 | Stealth feature set is explicitly adversarial to production WAFs; dual-use / policy risk | **Policy** | `crates/obscura-js/js/bootstrap.js`, `crates/obscura-net/src/wreq_client.rs` |

### Explicitly searched for and did NOT find
- Hardcoded telemetry / C2 / update-check URLs
- Encoded, compressed, or obfuscated payloads in `.rs` or `.js`
- `std::env::var` reads at runtime
- `fs::write` / `File::create` at runtime
- `Command::new` calls outside the CLI spawning sibling worker binaries
- `danger_accept_invalid_certs(true)`
- Binding to `0.0.0.0` or public interfaces
- Hardcoded crypto keys or signing bypass
- `unsafe` outside html5ever tree-sink interop
- Conditional compilation that adds network behavior under non-obvious feature flags
- Dependencies from sources other than crates.io
- Git-revision-pinned or path-remapped registry deps

---

## 7. Recommendations

1. **Do not run the pre-built tarballs.** Build from source (`cargo build --release`) after reading the diff. Pin to the current commit SHA, not `main`. Watch for rewritten history on the upstream branch.
2. **Sandbox at runtime.** Even with the good SSRF filter, the module loader gap is real. Run inside a container or firejail with egress restricted to the specific hosts you're scraping. Drop NET_RAW. No host-network mode.
3. **Close F5 locally if you care.** Patch `ObscuraModuleLoader::load` to call the same `validate_fetch_url` the main fetch path uses, or block ES-module imports entirely for your threat model.
4. **Audit transitive deps.** Run `cargo audit` against RUSTSEC and `cargo vet` / `cargo-crev` for the ~359 transitive crates. Pay attention to `deno_core`, `wreq`, `wreq-util`, and anything in the TLS stack.
5. **If you build stealth locally, verify the resulting binary against a clean-room rebuild** (two machines, same commit SHA, diff the output). The `continue-on-error` in the upstream workflow makes that workflow untrustworthy for stealth builds specifically.
6. **Don't use stealth features against sites that haven't consented.** This is a policy decision, not a technical one, but it's the larger risk than the code itself. The feature set is targeted at production WAFs; the intent of using it is what distinguishes lawful QA from adversarial scraping.
7. **Alternatives with a known maintainer:** `rquest` (Rust, same TLS-impersonation tech, longer-tenured author) + `playwright` with `playwright-stealth` or `undetected-chromedriver` covers equivalent JS-layer evasion with broader community review.

---

## 8. Method

- Full file enumeration under `crates/` (6 crates, ~12 kLOC Rust + ~3 kLOC JS).
- `cargo` / `Cargo.lock` inspection for dep sources, checksums, proc-macros.
- Targeted greps for: `unsafe`, `Command::new`, `std::env::var`, `fs::write` / `File::create`, `reqwest::Client` / `native_tls` / `danger_accept_invalid`, bind/`listen`/`TcpListener`, hardcoded `http[s]://` URLs, Deno ops, webdriver / fingerprint markers.
- Full read of: `bootstrap.js` (header + key stealth sections), `op_fetch_url`, `validate_fetch_url`, `main.rs`, `wreq_client.rs`, `module_loader.rs`, `tree_sink.rs`, `build.rs`, `release.yml`, `Cargo.toml` × 7.
- GitHub API check for repo creation date, star count, fork count, contributor count.
- No code was executed. No binary was run. No release tarball was downloaded.
