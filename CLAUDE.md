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

## Working style

Bias toward caution over speed. Use judgment for trivial tasks.

- **Think before coding.** Surface assumptions and uncertainty. If multiple
  interpretations exist, name them; don't pick silently. If a simpler approach
  is available, say so.
- **Simplicity first.** Minimum code that solves the problem. No speculative
  features, configurability, or error handling for impossible cases. If 200
  lines could be 50, rewrite it.
- **Surgical changes.** Every changed line should trace to the request. Don't
  "improve" adjacent code, comments, or formatting. Clean up only the orphans
  your change created — leave pre-existing dead code (including the
  fork-inherited mismatches below) alone unless asked.
- **Goal-driven.** Turn tasks into verifiable goals ("reproduce the bug in a
  test, then fix it"). For multi-step work, state a brief plan with a
  verification check per step.

## Workspace layout

Cargo workspace, 6 crates under `crates/`:

| Crate             | Role                                                                                                                  |
| ----------------- | --------------------------------------------------------------------------------------------------------------------- |
| `obscura-dom`     | Servo-derived DOM (html5ever, selectors)                                                                              |
| `obscura-net`     | HTTP client, cookie jar, tracker blocklist, robots.txt. Stealth: swaps in `wreq` for TLS fingerprint spoofing         |
| `obscura-js`      | V8 via `deno_core`; `js/bootstrap.js` provides navigator/document/fetch/XHR/Worker shims + anti-fingerprint overrides |
| `obscura-browser` | Page / BrowserContext orchestration                                                                                   |
| `obscura-cdp`     | Chrome DevTools Protocol server over WebSocket (binds 127.0.0.1 only)                                                 |
| `obscura-cli`     | Produces `obscura` and `obscura-worker` binaries. Subcommands: `serve`, `fetch`, `scrape`                             |

## Build & run

```bash
cargo build --release                       # default build
cargo build --release --features stealth    # + anti-detection + tracker blocking — LINUX ONLY (see Docker below)
cargo test                                  # unit tests live inline in src/
cargo test -p obscura-net                   # single crate — much faster once V8 is cached
cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings  # pre-PR
./scripts/verify-stealth.sh                 # sannysoft + creepjs bot-detection check (Linux-only; see Docker below)
```

- **First build ~5 min** — V8 compiles from source via `deno_core`. Cached after.
- Rust edition 2021. No MSRV pinned — check CI (`.github/workflows/ci.yml`) for the version actually tested.

### Stealth builds on macOS/Windows (Docker)

`--features stealth` pulls in `wreq` → `boring-sys2`, whose `prefix-symbols`
feature is broken on macOS/Windows: the C-side BoringSSL rename is skipped
but the Rust bindgen rename is applied, so every TLS symbol is unresolved
at link time. Run the stealth build and `verify-stealth.sh` via the
`obscura-stealth` Docker image (built from `scripts/Dockerfile.stealth`,
which bakes in `cmake` + `clang` + `libclang-dev` + `pkg-config` — raw
`rust:1.95` is missing all four and will fail with `is 'cmake' not
installed?` then `Unable to find libclang`):

```bash
# One-time: build the image. Rerun only if scripts/Dockerfile.stealth changes.
docker build -t obscura-stealth -f scripts/Dockerfile.stealth .

# Stealth build
docker run --rm \
  -v "$PWD":/src \
  -v obscura-cargo-registry:/usr/local/cargo/registry \
  -v obscura-linux-target:/src/target \
  obscura-stealth cargo build --release --features stealth

# Bot-detection verification (same image)
docker run --rm \
  -v "$PWD":/src \
  -v obscura-cargo-registry:/usr/local/cargo/registry \
  -v obscura-linux-target:/src/target \
  obscura-stealth bash scripts/verify-stealth.sh
```

The named volumes (`obscura-cargo-registry`, `obscura-linux-target`) persist
cargo's registry and the Linux target dir across runs — first run is ~5 min
(V8 from source), subsequent runs are fast. The Linux target volume is
isolated from your host `./target` (macOS build artifacts).

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
- `.github/workflows/release.yml` — tag-triggered release (push `v*` tag).
  Uses SHA-pinned actions + `attest-build-provenance`. Don't regress to tag pins.
- `.github/workflows/ci.yml` — per-PR gate: fmt + clippy + test + build on
  Linux/macOS/Windows. `--features stealth` only builds on Linux (wreq RC pulls
  in platform-specific TLS). Path-gated to skip on docs-only changes; if you
  add a new source path outside `crates/` or `Cargo.{toml,lock}`, extend the
  `paths:` filter so CI still runs.
- `crates/obscura-js/js/bootstrap.js` — ~125KB, most fingerprint logic lives here.
- `crates/obscura-cdp/src/server.rs` — CDP WebSocket server, 127.0.0.1-only bind.

## Project-local Claude Code skill

`.claude/skills/verify-stealth/SKILL.md` is checked into the repo — a project-
local skill that automates the Docker-based bot-detection verification flow
(sannysoft + creepjs). Triggers on changes to `bootstrap.js` or stealth code.
If you update the verify flow, keep the skill in sync.

## Fork-inherited mismatches (do not "fix" in passing)

- `LICENSE` and `README.md` say Apache 2.0, but `Cargo.toml` has `license = "MIT"`.
- `Cargo.toml` still has `repository = "https://github.com/h4ckf0r0day/obscura"`
  (upstream), not this fork's URL.

Both are known. Coordinate with the repo owner before changing either.
