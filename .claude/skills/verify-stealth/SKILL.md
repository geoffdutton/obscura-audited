---
name: verify-stealth
description: Use when the user asks to run verify-stealth, verify stealth, check the stealth build, or check bot-detection / fingerprint signals — also after modifying crates/obscura-js/js/bootstrap.js or any crates/obscura-net stealth code, before opening a PR that touches the stealth feature
---

# verify-stealth

## Overview

`scripts/verify-stealth.sh` runs the obscura stealth binary against live
`creepjs` and `bot.sannysoft.com` endpoints and reports PASS / WARN / FAIL
on ~26 fingerprint signals. The script is Linux-only because `boring-sys2`'s
`prefix-symbols` feature is broken on macOS/Windows (C-side rename is
skipped, bindgen rename is applied, producing unresolved linker symbols).

**Core principle:** on macOS/Windows, always route through the
`obscura-stealth` Docker image. Never try to run the script directly.

## Workflow

### 1. Platform check

- Linux host → run `./scripts/verify-stealth.sh` directly.
- Anything else (`uname -s` != `Linux`) → Docker.

### 2. Docker preflight (macOS/Windows)

- `docker version` must return a server version. If the daemon is down,
  ask the user to start their Docker backend (Rancher Desktop / Docker
  Desktop / OrbStack / Colima). Do **not** try to start it yourself.
- Ensure the `obscura-stealth` image exists; build it if not:
  ```bash
  docker image inspect obscura-stealth >/dev/null 2>&1 \
    || docker build -t obscura-stealth -f scripts/Dockerfile.stealth .
  ```
  (The image bakes in `cmake`, `clang`, `libclang-dev`, `pkg-config` —
  all four are required by `boring-sys2`. Raw `rust:1.95` is missing
  them.)

### 3. Run

```bash
docker run --rm \
  -v "$PWD":/src \
  -v obscura-cargo-registry:/usr/local/cargo/registry \
  -v obscura-linux-target:/src/target \
  obscura-stealth bash scripts/verify-stealth.sh
```

The two named volumes persist cargo's registry and the Linux target dir
across runs. First run is ~5 min (V8 from source); cached runs are fast.
Always mount both.

### 4. Background + monitor

Because the first build can take 5+ min, launch the container in the
background (output → `/tmp/verify-stealth.log`, exit code → a sentinel
file) and attach a `Monitor` that greps for progress markers:

```
Building obscura | Binary: | ── section | PASS | WARN | FAIL | Results: | error[ | error: | panicked at
```

Pass `--json` to the script if you want machine-readable output.

### 5. Reporting

The script exits **1 on any FAIL** — that's a legitimate fingerprint
regression, not an infrastructure error. Always surface:

- The final `Results: N/M passed  |  N warn  |  N failed` line.
- Every `FAIL` and `WARN` line verbatim, grouped by the four sections
  (Core navigator/window, API completeness, CreepJS, Sannysoft).

Only call the run "broken" if the log contains `error[`, `panicked at`,
or `is \`cmake\` not installed?`-style build failures.

## Signal → likely root cause

| FAIL signal | Most common cause |
|---|---|
| `Internal globals visible: __obscura_*, _fp*` | `bootstrap.js` has top-level `var`/`function` that hoists onto `globalThis`. Wrap internals in an IIFE. |
| `typeof Deno != undefined` | Bootstrap didn't `delete globalThis.Deno` at end. |
| `navigator.plugins toString = [object Array]` | Missing `Symbol.toStringTag` on the plugins shim (or not using real PluginArray prototype). |
| `AudioContext.addEventListener = undefined` | AudioContext shim isn't wired through EventTarget. |
| `WebGL getParameter(VERSION) = 0` / `gl.<method> = undefined` | WebGL stub returning raw enums / missing methods. |
| `SVG getBBox is not a function` | SVGGraphicsElement API not implemented. |
| `FontFace = undefined` | Constructor not exposed on `globalThis`. |
| `Canvas gradient fillText: css.startsWith is not a function` | `_parseColor` assumes fillStyle is a string; needs a CanvasGradient/CanvasPattern branch. |
| `totalLies = N` (N > 20) | Almost always an aggregate of the Section 2 API gaps above — fix those first and this drops. |

## Common mistakes

- **Running the script directly on macOS** → hits the platform guard and
  exits 1 with the Docker hint. Use the container.
- **Using raw `rust:1.95`** → build fails first with `is cmake not installed?`,
  then with `Unable to find libclang`. Use the `obscura-stealth` image.
- **Omitting the named volumes** → every run pays the full V8 compile.
- **Reading exit 1 as "Docker broke"** → check the `Results:` line first.
- **Polling `tail` in a loop** → use a Monitor with a grep filter on
  progress markers.
