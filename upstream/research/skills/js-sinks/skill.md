---
name: js-sinks
description: Map dangerous sinks, sources, and gadgets in collected JavaScript during authorized bug bounty or security testing, including DOM XSS sinks, postMessage handlers, open redirects, prototype pollution patterns, and taint flows from attacker-controlled input to risky functions. Use this skill whenever the user has collected or deobfuscated JS and wants to find eval/innerHTML/document.write sinks, check postMessage origin handling, hunt prototype pollution, run Semgrep or CodeQL taint rules on a bundle, or build a gadget table, even if they just say "find the dangerous functions". Expects input from js-collect.
---

# JS Sinks

Goal: a prioritized table of places where attacker-controlled data can reach a dangerous function, with an honest confidence level for each.

> Authorized testing only. Static analysis finds candidates, not vulnerabilities. Never report a flow as a finding until you've confirmed it in the running app.

## Input

`js-collect-output/<target>/processed/` (and recovered sources in `sourcemaps/`). Work on unpacked, beautified code. Minified one-liners make results unreadable.

## Workflow

### 1. Quick triage
A fast first pass to see what's there. Plain search is fine here, as long as you treat hits as leads and not conclusions.

**Sources** (attacker-influenced data): `location.search`, `location.hash`, `location.pathname`, `document.referrer`, `window.name`, `document.cookie`, `localStorage`/`sessionStorage`, `postMessage` payloads, URL parameters parsed into objects, server responses rendered into the DOM.

**Sinks:**
- Code execution: `eval`, `new Function`, `setTimeout`/`setInterval` with a string, `import()` with a variable path, dynamic `<script>` creation, JSONP callbacks
- HTML injection: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`, jQuery `.html()`/`.append()` with variables
- Navigation: assignments to `location` / `location.href`, `window.open`, `postMessage` target origins
- Other: `fetch`/`XMLHttpRequest`/`WebSocket` to user-controlled URLs, hardcoded crypto keys, `Math.random` used for tokens

**Message handlers:** every `addEventListener('message', ...)`. Does it check `event.origin`? Is the check exact or a loose `indexOf`/`endsWith`?

### 2. Prototype pollution candidates
Look for code that writes to objects using attacker-influenced keys:
- Recursive merge/extend/clone/deep-set functions (`merge`, `extend`, `defaultsDeep`, `set`, `$.extend(true, ...)`) with no guard against `__proto__`, `constructor`, and `prototype`
- `for...in` copies without a `hasOwnProperty` check
- Bracket assignment `obj[a][b] = c` where `a`/`b` come from input (query string, JSON, hash)
- Query-string or hash parsers that build nested objects

Then look for **gadgets**: places that read a property that might be missing and fall through to the prototype (script `src`, template options, config flags, `innerHTML`-bound fields). A pollution source with no reachable gadget has low impact.

### 3. Taint analysis
Use a static taint tool instead of reading flows by eye.
- **Semgrep** (JavaScript taint-mode rules): define sources and sinks from step 1, run against `processed/`.
- **CodeQL** (JavaScript/TypeScript): build a database from the recovered sources and run the standard DOM-XSS, prototype-pollution, and open-redirect queries.
- Keep the rules and queries you used in the output folder so the run is repeatable.

Bundled and transpiled code can break flow tracking. Prefer recovered original sources when a sourcemap gave them.

### 4. Cross-reference known gadgets
Before assigning confidence, compare each candidate against public references: published client-side prototype-pollution gadget lists, PortSwigger research on DOM XSS and prototype pollution, and advisories for the specific library versions in use. A match gets a reference link and a confidence bump. Anything unmatched stays a candidate.

### 5. Dynamic confirmation
Only for in-scope targets, only with benign markers.
- Put a breakpoint on the suspected sink or gadget getter.
- Replay the input in the running app using a harmless marker (a unique string logged to the console), not a payload that reads data or changes state.
- Capture the file and line from the stack trace.
- Confirm on your own account and test data only.

Only a flow you reproduced gets `confidence: high`.

## Output: `gadgets.md`

| File | Line | Sink / gadget | Source | Reachable from (route/feature) | Confidence | Known reference | Notes |
|------|------|---------------|--------|--------------------------------|------------|-----------------|-------|

Confidence:
- **high**: reproduced in the running app
- **medium**: static taint flow found, not yet reproduced
- **low**: sink present, no source reaching it found
- **candidate**: pattern match only

End the file with the five highest-value leads and the manual test you'd run for each. Hand the table to `js-analyse` to join with routes and the feature map.
