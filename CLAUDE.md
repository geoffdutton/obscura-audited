# CLAUDE.md

## Repository context

**Public repo** — `github.com/geoffdutton/obscura-audited`. Audited fork of
`h4ckf0r0day/obscura` (pseudonymous upstream, ~10 days old at fork time — see
`AUDIT.md` for the trust assessment driving this fork).

Everything committed is world-readable: code, commit messages, PR bodies,
issue comments, `gh pr review` bodies, review replies. Treat the whole repo
as a public artifact.

## Commit / PR hygiene (public repo)

- **No session-identifying links** in commits, PRs, issue comments, or review
  replies. Specifically: no `claude.ai/chat/...`, no `claude.ai/share/...`, no
  internal telemetry IDs, no `gsd`/agent session UUIDs.
- `Co-authored-by: Claude <noreply@anthropic.com>` on commits is fine.
- Never commit: `.env`, local scratch, binary artifacts, `target/`, anything
  that isn't already public in this fork's surface. If in doubt, ask first.
- Stage files by name, not `git add -A`.

## Workspace layout

Cargo workspace, 6 crates under `crates/`:

| Crate | Role |
|---|---|
| `obscura-dom` | Servo-derived DOM (html5ever, selectors) |
| `obscura-net` | HTTP client, cookie jar, tracker blocklist, robots.txt. Stealth: swaps in `wreq` for TLS fingerprint spoofing |
| `obscura-js` | V8 via `deno_core`; `js/bootstrap.js` provides navigator/document/fetch/XHR/Worker shims + anti-fingerprint overrides |
| `obscura-browser` | Page / BrowserContext orchestration |
| `obscura-cdp` | Chrome DevTools Protocol server over WebSocket (binds 127.0.0.1 only) |
| `obscura-cli` | Produces `obscura` and `obscura-worker` binaries. Subcommands: `serve`, `fetch`, `scrape` |

## Build & run

```bash
cargo build --release                       # default build
cargo build --release --features stealth    # + anti-detection + tracker blocking
cargo test                                  # unit tests live inline in src/
./scripts/verify-stealth.sh                 # sannysoft + creepjs bot-detection check
```

- **First build ~5 min** — V8 compiles from source via `deno_core`. Cached after.
- Requires Rust 1.75+ (edition 2021).

## Stealth feature: how it propagates

`obscura-cli/stealth` → `obscura-browser/stealth` + `obscura-net/stealth`.
When touching anti-detection code, check both: the net crate handles TLS /
JA3-JA4 fingerprinting (via `wreq` RCs, only compiled under `--features
stealth`), and the browser/JS crates handle navigator/fingerprint overrides.

## JS bootstrap gotchas

`crates/obscura-js/js/bootstrap.js` runs inside V8. Known leak patterns —
see `docs/bot-detection-audit.md` before editing:

- `function`/`var` at top level get hoisted onto `globalThis` — wrap bootstrap
  internals in an IIFE so `_fp*`, `__obscura_*`, and similar don't appear in
  `Object.keys(window)`.
- `window.Deno` is visible by default. Delete it at the end of bootstrap.
- Never rely on `navigator.webdriver = undefined`; real Chrome doesn't have
  the property at all. Needs `delete` + prototype scrubbing.

## Key files to know

- `AUDIT.md` — supply-chain + source audit. Read before changing release workflow.
- `docs/bot-detection-audit.md` — stealth effectiveness, known fingerprint leaks.
- `.github/workflows/release.yml` — tag-triggered release. Uses SHA-pinned
  actions + `attest-build-provenance`. Don't regress to tag pins.
- `crates/obscura-js/js/bootstrap.js` — 124KB, most fingerprint logic lives here.
- `crates/obscura-cdp/src/server.rs` — CDP WebSocket server, 127.0.0.1-only bind.

## License note

`LICENSE` is Apache 2.0, `README.md` says Apache 2.0, but `Cargo.toml` says
`license = "MIT"`. Known mismatch from upstream. Don't "fix" in passing —
coordinate with the repo owner.
