# Obscura security & trust audit

**Audit date:** 2026-04-23
**Commit audited:** `b00a1f2` (tip of `main` at audit time)
**Last status update:** 2026-04-24
**Upstream:** `github.com/h4ckf0r0day/obscura` (created 2026-04-13, 10 days old at audit time)
**Scope:** full source tree — 6 crates, ~12 kLOC Rust + ~3 kLOC bundled JS
**Out of scope:** contents of the pre-built release tarballs on GitHub Releases (see §3)

---

## TL;DR

The **source** is materially tamer than the surface signals suggest. It is a real headless-browser project doing what the README claims, with surprisingly strong baseline hardening (SSRF filter, localhost-only bind, in-memory state, tight JS↔Rust op surface). No beacons, no exfil, no update-channel, no env-var reads, no disk persistence, no hidden listeners, no obfuscated payloads, no shell execution surface exposed to rendered JS, no `danger_accept_invalid_certs`, no `unsafe` outside three legitimate html5ever interop lines.

The **distribution layer** is the real problem. The pre-built tarballs are not cryptographically bound to this source: no signatures, no SHA256SUMS, no SLSA provenance, tag-pinned (not SHA-pinned) actions, and a `continue-on-error: true` on the stealth build step that lets a stealth-featured release silently diverge from the default build. Combined with the author's pseudonymous handle, the 10-day-old repo, and the anomalously high star velocity (1,681 stars / 123 forks in 10 days), the releases should be treated as unsigned third-party binaries from an unvetted author.

**Bottom line:** build from source. Do not `curl | tar x` the releases.

### Remediation status (as of 2026-04-24)

All four actionable code/CI findings from this audit (F1, F2, F3, F5) are addressed on `main` with test coverage in the audited fork. The release pipeline now publishes SHA256 sidecars and SLSA build provenance, drops `continue-on-error` on the stealth build, and pins every action to a commit SHA. The ES module loader goes through an origin-aware Private Network Access filter that blocks the IMDS / localhost cases called out in §4.2, verified by 18 passing PNA tests in `obscura-net`. Per-finding status is recorded in the tables in §3.1 and §6; resolution detail and commit references are in §9.

Out of scope of this fork and deliberately deferred: F4 (upstream trust signal), F6 (license mismatch — coordinate with upstream author per `CLAUDE.md`), F7 (wreq RCs — mitigated by only compiling under `--features stealth`), F8/F9/F10 (Low / by-design), F11 (policy).

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
| License | README: Apache 2.0. LICENSE file: Apache 2.0 text. `Cargo.toml`: `license = "MIT"` | **Mismatch**. Likely just needs Cargo.toml update--up to upstream author. |

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

| # | Issue | Severity | Status (2026-04-24) |
|---|---|---|---|
| R1 | No SHA256SUMS file published with releases | High | **Fixed** — `.sha256` sidecar emitted per artifact and uploaded alongside the tarball/zip (`release.yml:50,59-60,74-81`). |
| R2 | No cosign / sigstore signing | High | **Fixed (via SLSA)** — Sigstore-backed build provenance attached per artifact via `actions/attest-build-provenance` (`release.yml:62-72`); verifiable with `gh attestation verify`. |
| R3 | No SLSA provenance / `--attestations` | Medium | **Fixed** — same attestation step; `id-token: write` / `attestations: write` permissions added at workflow scope (`release.yml:8-11`). |
| R4 | No reproducible-build documentation | Medium | Deferred (documentation task, not a supply-chain gate). |
| R5 | `continue-on-error: true` on the stealth build | Medium | **Fixed** — removed; stealth build is now a required step (`release.yml:41-42`). |
| R6 | Actions pinned by tag, not commit SHA | Medium | **Fixed** — all actions SHA-pinned with tag retained as comment; weekly Dependabot updates configured (`.github/dependabot.yml`). |
| R7 | Compromised runner could swap the tarball before upload without detection | Medium | **Mitigated** — SHA256 sidecar + SLSA attestation bind artifact → source commit → builder identity. A swap would break both. |

**Read:** the workflow builds from the same source you can read, but there is no mechanism to prove that the binary you `curl`ed is the output of this workflow for this commit. Treat the tarballs as unsigned third-party binaries.

**Update (2026-04-24):** the above paragraph described the upstream audit state. In this fork, the binding exists: consumers can verify with `shasum -a 256 -c obscura-x86_64-linux.tar.gz.sha256` and `gh attestation verify obscura-x86_64-linux.tar.gz --repo geoffdutton/obscura-audited`. The advice to build from source still stands for users who don't want to trust GitHub's attestation infrastructure.

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

**Gap (at audit time — now fixed, see below):** `ObscuraModuleLoader::load` (`crates/obscura-js/src/module_loader.rs:47-92`) fetches ES modules over HTTP with **no such validation**. A rendered page can do:

```js
await import('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
```

…and the module loader will fetch and (attempt to) execute it. This is a real SSRF vector if you ever run this headless browser against hostile pages in a cloud environment.

**Update (2026-04-24):** the module loader now calls `validate_pna(&target, RequestInitiator::Page(&base_url))` before any network IO (`crates/obscura-js/src/module_loader.rs:66-68`). `base_url` that doesn't parse falls back to a synthetic `https://unknown.invalid` so the initiator is treated as public and private targets remain blocked (`module_loader.rs:62-64`). The legacy `validate_fetch_url` was superseded by an origin-aware Private Network Access filter: the target's address space (`Public` / `Private` / `Local`) is compared against the initiator's, and a page-initiated fetch is blocked iff the target is strictly more private. Top-level navigations (the CLI `obscura fetch http://localhost` path) remain allowed. Covered by 18 tests in `crates/obscura-net/src/client.rs::pna_tests`, including the IMDS scenario (`page_public_to_private_is_blocked`). See §9.

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

| # | Finding | Severity | Location | Status (2026-04-24) |
|---|---|---|---|---|
| F1 | Pre-built release tarballs lack signatures, checksums, provenance | **High** (distribution) | `.github/workflows/release.yml` | **Fixed** — SHA256 sidecars + SLSA provenance via `actions/attest-build-provenance`. Commits `d65a553`, `2a58a8f`. |
| F2 | `continue-on-error: true` on stealth build lets artifact silently diverge | Medium | `.github/workflows/release.yml:41` | **Fixed** — `continue-on-error` removed (`release.yml:41-42`). Commit `2a58a8f`. |
| F3 | GitHub Actions pinned by tag, not commit SHA | Medium | `.github/workflows/release.yml:30-58` | **Fixed** — every action SHA-pinned with semver-tag comment; Dependabot configured for weekly updates. Commits `560b96e`, `2a58a8f`. |
| F4 | Author is pseudonymous (`h4ckf0r0day`) with 10-day-old repo and anomalous star velocity | Signal | upstream metadata | N/A — upstream trust signal, not addressable in this fork. Fork origin disclosed in `CLAUDE.md` and `README.md`. |
| F5 | `ObscuraModuleLoader::load` fetches ES modules without SSRF filter — bypasses the filter that guards `op_fetch_url` | **Medium** (runtime, with hostile-page threat) | `crates/obscura-js/src/module_loader.rs:47-92` | **Fixed** — now calls `validate_pna(&target, RequestInitiator::Page(&base_url))` before network IO (`module_loader.rs:66-68`), with fail-closed fallback on unparseable `base_url` (`:62-64`). Origin-aware PNA model replaces the flat public-only filter. 18 passing PNA tests including the IMDS case. Commits `1a187ca`, `5e4d76d`. |
| F6 | License declaration mismatch (`Cargo.toml` = MIT; LICENSE + README = Apache 2.0) | Low | `Cargo.toml:15` | **Deferred** — per `CLAUDE.md`, coordinate with upstream author before touching license metadata. |
| F7 | Stealth dependencies (`wreq`, `wreq-util`) are release candidates from an ecosystem with typosquat / handoff history | Low | `crates/obscura-net/Cargo.toml` | **Mitigated** — only compiled under `--features stealth` (Linux-only in CI). Open: track for a stable `wreq` release before tagging a stealth build. |
| F8 | README benchmarks unverifiable (no reproducer, no methodology) | Low / non-security | `README.md` | Not addressed (non-security, documentation task). |
| F9 | Multi-worker load balancer does raw TCP forwarding with 4-byte peek; safe on 127.0.0.1, unsafe if ever exposed | Low | `crates/obscura-cli/src/main.rs:203-238` | **By design** — localhost-only; audit flagged as Low conditional on future exposure. |
| F10 | `Worker` shim uses `new Function(...)` to execute worker code | Low (by-design) | `crates/obscura-js/js/bootstrap.js:2582` | **By design** — required for the Worker shim. |
| F11 | Stealth feature set is explicitly adversarial to production WAFs; dual-use / policy risk | **Policy** | `crates/obscura-js/js/bootstrap.js`, `crates/obscura-net/src/wreq_client.rs` | Policy, not code. Addressed by disclosure in README and §5.4 here. |

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

---

## 9. Remediation detail (2026-04-24)

This section documents how each Fixed/Mitigated finding was addressed in the fork and how to re-verify. It is additive to the original audit — no prior text has been deleted.

### 9.1 F1 / R1–R3 / R7 — release artifact provenance

Workflow: `.github/workflows/release.yml` (commits `d65a553`, `2a58a8f`).

- `id-token: write` and `attestations: write` added at workflow scope (`:8-11`).
- Per-artifact SHA256 sidecar generated with `shasum -a 256` on Unix (`:50`) and `Get-FileHash` on Windows (`:59-60`).
- Per-artifact SLSA build provenance attached via `actions/attest-build-provenance@a2bbfa25…` (`:62-72`). Ties the artifact to the GitHub-runner identity and the source commit.
- `softprops/action-gh-release` uploads both the artifact and its `.sha256` sidecar (`:74-81`).

Consumer verification:

```bash
# integrity
shasum -a 256 -c obscura-x86_64-linux.tar.gz.sha256
# provenance + source commit
gh attestation verify obscura-x86_64-linux.tar.gz --repo geoffdutton/obscura-audited
```

### 9.2 F2 / R5 — stealth build no longer swallows failures

`release.yml:41-42` — the stealth build step no longer has `continue-on-error: true`. Because the stealth build overwrites the non-stealth binary at the same `target/.../obscura` path, tolerating stealth failures previously produced tarballs whose stealth status depended on whether the second `cargo build` happened to succeed. Commit `2a58a8f`.

### 9.3 F3 / R6 — SHA-pinned actions + Dependabot

Every action is now pinned to a 40-character commit SHA with the semver tag retained as a trailing comment:

| Action | Pinned SHA | Tag |
|---|---|---|
| `actions/checkout` | `de0fac2e4500dabe0009e67214ff5f5447ce83dd` | `v6.0.2` |
| `dtolnay/rust-toolchain` | `29eef336d9b2848a0b548edc03f92a220660cdb8` | `stable` |
| `actions/attest-build-provenance` | `a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32` | `v4.1.0` |
| `softprops/action-gh-release` | `b4309332981a82ec1c5618f44dd2e27cc8bfbfda` | `v3.0.0` |

`.github/dependabot.yml` opts into weekly updates for the `github-actions` ecosystem so pins don't stagnate. Commits `560b96e`, `2a58a8f`.

### 9.4 F5 — module-loader SSRF, refined into origin-aware PNA

Two-step fix. Commit `1a187ca` closed the raw bypass (the module loader now calls the same filter as `op_fetch_url`). Commit `5e4d76d` replaced the flat filter with Chrome's Private Network Access model because the initial fix rejected legitimate top-level navigations like `obscura fetch http://localhost`.

The PNA model lives in `crates/obscura-net/src/client.rs`:

- `AddressSpace` enum — `Public` / `Private` / `Local`, mirroring Chromium's three-tier classification.
  - `Local`: IPv4/IPv6 loopback, `localhost` and `*.localhost`.
  - `Private`: RFC1918 (`10/8`, `172.16/12`, `192.168/16`), IPv4 link-local (`169.254/16`), IPv6 ULA (`fc00::/7`), IPv6 link-local (`fe80::/10`).
  - `Public`: everything else.
- `validate_pna(target, initiator)` where `initiator` is one of:
  - `RequestInitiator::TopLevel` — user-initiated; scheme check only.
  - `RequestInitiator::Page(&Url)` — page-initiated; blocked iff target is strictly more private than initiator.

Module-loader wiring (`crates/obscura-js/src/module_loader.rs:66-68`):

```rust
validate_pna(&parsed, RequestInitiator::Page(&initiator))
    .map_err(|e| io_err(format!("Refused to load module {}: {}", url, e)))?;
```

Fail-closed fallback (`:62-64`) — if the page's `base_url` doesn't parse, the initiator becomes a synthetic `https://unknown.invalid`, so unparseable origins are treated as public and cannot reach private/local targets.

Test coverage — `crates/obscura-net/src/client.rs::pna_tests`, 18 tests:

- Address-space classification: RFC1918 boundaries, IPv4 loopback/link-local, IPv6 loopback/link-local/ULA, `.localhost` suffix, public addresses.
- Full PNA decision matrix: `TopLevel` always allowed; `page_public_to_private_is_blocked` (the IMDS case, `169.254.169.254` from a public page); `page_public_to_local_is_blocked`; `page_private_to_local_is_blocked`; `page_private_to_private_is_allowed` (so `10.0.0.5` can fetch from `10.0.0.6`); `page_local_to_anything_is_allowed`; `unparseable_origin_treated_as_public_initiator`; non-HTTP scheme rejection regardless of initiator.

Re-verify: `cargo test -p obscura-net --lib` → 35 passed, 0 failed (includes all 18 PNA tests).

### 9.5 Known gaps / follow-ups

- **No direct integration test for `ObscuraModuleLoader::load`.** Coverage is transitive through `validate_pna`; the fallback path at `module_loader.rs:62-64` isn't exercised end-to-end. Worth a small test constructing the loader with an empty/invalid `base_url` and asserting that `http://169.254.169.254/` still rejects.
- **F7 not closed.** `wreq 6.0.0-rc.28` and `wreq-util 3.0.0-rc.10` remain pinned. Monitor upstream for a stable release before tagging a stealth build.
- **Recommendation §7.3 is obsolete.** That recommendation told consumers to close F5 locally. F5 is closed in this fork.
- **Recommendation §7.1 stands** for consumers who prefer not to trust GitHub's attestation infrastructure. Build-from-source remains the conservative default; SHA256 + SLSA provenance is for consumers who will trust `gh attestation verify`.
