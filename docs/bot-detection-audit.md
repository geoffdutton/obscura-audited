# Stealth Mode Bot Detection Audit

Ran `obscura fetch --stealth` against both standard bot-detection test pages.
Build: `cargo build --release` (v0.1.0, 71 MB binary). Results ordered by severity.

---

## Test pages

| Page | Network result |
|---|---|
| `https://bot.sannysoft.com/` | Cloudflare returns `503 "DNS cache overflow"` to bare `curl` (no UA). With a real Chrome UA header: `200`. With `obscura fetch --stealth`: **loads fine** — TLS fingerprint clears Cloudflare. |
| `https://abrahamjuliot.github.io/creepjs/` | Loads fine, no blocked scripts. Single `creep.js` + `style.min.css`. |

No PGL blocklist hits observed for either site. The sannysoft page pulls three CDN scripts at
runtime (`lodash`, `jquery`, `ua-parser-js` from `cdnjs.cloudflare.com` / `cdn.jsdelivr.net`) — none blocked.

---

## 🔴 Critical — Runtime identity leakage

### `window.Deno` is exposed

```js
typeof Deno          // "object"
typeof Deno.core     // "object"
'Deno' in window     // true
```

Any page that runs `typeof Deno !== 'undefined'` immediately fingerprints the underlying runtime.
CreepJS reports `Deno` inside `windowFeatures.keys` (271 total window keys enumerated).

### Internal bootstrap globals in `Object.keys(window)`

The following names are enumerable on `window` and will be detected by any script that enumerates
or probes window properties:

```
_markNative  _fpRand  _fpNoise  _fpCache  _getFp  _fp
_wrap  _wrapEl  _resolveUrl  _registerIframe
__obscura_ua  __obscura_css  __obscura_click_target
```

Root cause: `function` declarations and `var` at bootstrap top-level are hoisted onto `globalThis`,
and `globalThis.__obscura_*` assignments are directly enumerable.

**Fix:** Wrap all bootstrap internals in an IIFE so they don't pollute `globalThis`, then delete
`Deno` from `globalThis` at the end:
```js
delete globalThis.Deno;
```

---

## 🔴 Critical — `navigator.webdriver` leaks its existence

**Sannysoft result: FAILED — "present (failed)"**

```js
// bootstrap.js:1017
get webdriver() { return undefined; },
```

Because a getter is defined, `'webdriver' in navigator` returns `true`. The sannysoft / fpCollect
check is:

```js
return 'webdriver' in navigator;  // → true → FAIL
```

In real Chrome (non-automation), the `webdriver` property does **not exist at all**.
`'webdriver' in navigator` returns `false`.

**Fix:** Remove the `get webdriver()` getter entirely. Do not define it. If a script reads
`navigator.webdriver` it will get `undefined` naturally, and `'webdriver' in navigator` will
return `false`.

---

## 🔴 Critical — `Function.prototype.toString` masking detected (7 channels)

**CreepJS: 7 failures on `Function.toString`**

```
failed class extends error
failed "prototype" in function
failed descriptor
failed own property
failed descriptor keys
failed own property names
failed own keys names
```

The `_markNative` / `Set`-based toString override passes the basic `fn.toString()` call but fails
when creepjs inspects class extension behavior, prototype presence, and
`Object.getOwnPropertyDescriptor` on the function itself. Native browser functions have a specific
shape that this approach cannot replicate.

---

## 🔴 Critical — `Element.*` prototype descriptors missing (100+ checks)

**CreepJS: "failed descriptor.value undefined" on virtually every Element property**

```
innerHTML, className, style, children, clientWidth, offsetWidth,
childElementCount, dataset, id, tagName, outerHTML, innerText, ...
```

CreepJS checks `Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML')` etc. Since element
properties in Obscura are JavaScript-level own-properties on instances rather than getter/setter
descriptors on `Element.prototype`, the descriptor lookups return `undefined`.

Real browsers define all these as prototype-level accessors, e.g.:
```js
Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML')
// → { get: ƒ, set: ƒ, enumerable: true, configurable: true }
```

---

## 🟠 High — `navigator.plugins` wrong type

**Sannysoft result: FAILED — "Plugins is of type PluginArray"**

```js
Object.prototype.toString.call(navigator.plugins)
// → "[object Array]"   ← detected
// should be "[object PluginArray]"
```

**Fix:** Define a `PluginArray` class whose `Symbol.toStringTag` returns `"PluginArray"`, and
return an instance of it from the `plugins` getter.

---

## 🟠 High — `window.chrome` fails deeper inspection

**Sannysoft result: FAILED — Chrome (New) "missing (failed)"**

`window.chrome` exists with `app`, `runtime`, `csi`, `loadTimes`. But `fpCollect.hasChrome()`
performs deeper checks (prototype chain, descriptor shape) that our plain-object `chrome` does not
pass.

---

## 🟠 High — `AudioContext` / `OfflineAudioContext` incomplete

**Console errors:**
```
TypeError: Cannot read properties of undefined (reading 'sampleRate')
TypeError: Cannot read properties of undefined (reading 'maxValue')
TypeError: Cannot read properties of undefined (reading 'minValue')
TypeError: context.addEventListener is not a function
```

**CreepJS:**
```
AnalyserNode.getFloatFrequencyData: expected -Infinity (silence) and got 1024 frequencies
```

- `OfflineAudioContext` constructor exists but returned node lacks `sampleRate`, `maxValue`,
  `minValue` properties
- `AudioContext` instance has no `addEventListener`
- `AnalyserNode.getFloatFrequencyData` should return `-Infinity` (silence) for a headless context;
  returns 1024 non-zero values instead

---

## 🟠 High — `Date` methods fail instanceof checks

**CreepJS: all `Date.*` methods — "failed at instanceof check error"**

`Date.prototype.getTime`, `Date.prototype.toString`, etc. fail instanceof/prototype checks.
Likely a Deno V8 environment difference from browser V8.

---

## 🟡 Medium — Canvas2D `_parseColor` crashes on gradient/pattern styles

**Console error:**
```
TypeError: css.startsWith is not a function
    at _Canvas2D._parseColor (<obscura:bootstrap>:2142:13)
    at drawOutlineOfText
```

`_parseColor(css)` at `bootstrap.js:2142` calls `css.startsWith('#')` unconditionally. When
`fillStyle` or `strokeStyle` is set to a `CanvasGradient` or `CanvasPattern` object (valid per
spec), `css` is not a string and `.startsWith` throws.

**Fix (`bootstrap.js:2140`):**
```js
_parseColor(css) {
  if (!css || css === 'none') return [0,0,0,0];
  if (typeof css !== 'string') return [0,0,0,255]; // CanvasGradient/CanvasPattern
  if (css.startsWith('#')) { ... }
  ...
}
```

---

## 🟡 Medium — SVG `getBBox()` not implemented

**Console error:**
```
TypeError: svgBox.getBBox is not a function
    at getSVG
```

`SVGSVGElement.getBBox()` is missing. Should return a `DOMRect` with the bounding box.

---

## 🟡 Medium — `FontFace` not defined

**Console error:**
```
ReferenceError: FontFace is not defined
    at getFontFaceLoadFonts
```

`FontFace` constructor is absent from `window`. CreepJS uses it to probe installed fonts.

---

## 🟡 Medium — `iframe.contentDocument` inaccessible

**Console error:**
```
TypeError: Cannot read properties of undefined (reading 'document')
    at getBehemothIframe / getPhantomIframe
```

`HTMLIFrameElement.contentDocument` and `contentWindow` return `undefined`. CreepJS (and
sannysoft's `HEADCHR_IFRAME` test) use this to check whether the iframe `chrome` object is
consistent with the parent.

---

## 🟡 Medium — WebGL context methods missing

**Console errors:**
```
TypeError: gl.uniform2f is not a function
TypeError: gl.getContextAttributes is not a function
```

`WebGLRenderingContext` exists in window but the context object returned by
`canvas.getContext('webgl')` is missing many methods. `getParameter(gl.VERSION)` returns `0`
instead of a version string. GPU vendor/renderer spoofing (`WEBGL_debug_renderer_info`) does not
work end-to-end.

---

## 🟡 Medium — `getClientRects()` returns too few rects

**Console error:**
```
TypeError: Cannot destructure property 'top' of 'elementClientRects[3]' as it is undefined.
```

`element.getClientRects()` returns 1 `DOMRect`. CreepJS expects ≥ 4 for a text element spanning
multiple lines.

---

## ✅ Passing / OK

| Check | Status |
|---|---|
| User Agent — Chrome 145 | ✅ Passed (sannysoft + creepjs) |
| `navigator.userAgentData` (high-entropy) | ✅ Correct shape, accepted |
| `HeadlessChrome` in UA | ✅ Not present |
| `navigator.permissions` — notifications `prompt` | ✅ Correct |
| `speechSynthesis` / voices ("Google US English") | ✅ Accepted |
| Battery, hardwareConcurrency, deviceMemory | ✅ Accepted |
| `window.chrome.app` / `chrome.runtime` shape | ✅ Accepted |
| Tracker/ad domain blocking (PGL list) | ✅ No false positives on test sites |

---

## CreepJS summary score

```json
{
  "totalLies": 260,
  "trash": [],
  "resistance.engine": "Blink"
}
```

260 detected lies is very high — any real anti-bot system scoring on creepjs data would flag this
immediately. The dominant sources are the Deno runtime leakage, `Function.toString` masking
failures, and missing Element prototype descriptors.

---

## Sannysoft results summary

| Test | Result |
|---|---|
| User Agent (Old) | ✅ PASSED |
| WebDriver (New) | ❌ FAILED — "present" (`'webdriver' in navigator === true`) |
| WebDriver Advanced | ❌ FAILED — deeper `$cdc_*`/`$wdc_*` checks |
| Chrome (New) | ❌ FAILED — "missing" (deeper chrome object checks) |
| Permissions (New) | ❌ FAILED (async result empty) |
| Plugins Length (Old) | ❌ FAILED (async result empty) |
| Plugins is of type PluginArray | ❌ FAILED (`[object Array]` instead of `[object PluginArray]`) |
| Languages (Old) | ❌ FAILED (async result empty) |
| WebGL Vendor / Renderer | ❌ empty — `getParameter()` returns `0` |
| fpScanner table | ❌ completely empty — async CDN pipeline didn't finish |
