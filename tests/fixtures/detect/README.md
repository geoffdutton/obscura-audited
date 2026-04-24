# Detection fixtures

One HTML fixture per bot-detection rule. Each page writes a JSON result to
`document.title`; the `detect_runner` integration test asserts the expected
value after fetching via `obscura fetch --features stealth`.

## Fixtures

| File | Rule | Assertion |
|------|------|-----------|
| `element_descriptors.html` | Rule 2 — Element.prototype descriptors | `missing.length === 0` |

## Regenerating the golden property list

`element_prototype.json` captures the accessor properties that must have own
descriptors on `Element.prototype`. To regenerate from Chrome 145 Linux:

```js
// Run in Chrome 145 DevTools console
const ownAccessors = n =>
  Object.getOwnPropertyNames(n).filter(k =>
    Object.getOwnPropertyDescriptor(n, k)?.get);

JSON.stringify([
  ...ownAccessors(Element.prototype),
  // Obscura collapses HTMLElement into Element, so include these too:
  ...ownAccessors(HTMLElement.prototype),
].filter((v, i, a) => a.indexOf(v) === i));
```

Commit the output as `element_prototype.json` and update the `EXPECTED` array
in `element_descriptors.html` to match.
